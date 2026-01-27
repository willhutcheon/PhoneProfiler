using Microsoft.Azure.Functions.Worker;
using Microsoft.Azure.Functions.Worker.Http;
using Microsoft.Data.SqlClient;
using Microsoft.Extensions.Logging;
using System.Data;
using System.Net;
using System.Security.Cryptography;
using System.Text;
using System.Text.Json;

#region Helpers
internal static class HttpJson
{
    public static async Task<HttpResponseData> WriteAsync(HttpRequestData req, HttpStatusCode status, int errorCode, string errorText, object response = null)
    {
        var resp = req.CreateResponse(status);
        await resp.WriteAsJsonAsync(new
        {
            ErrorCode = errorCode,
            ErrorText = errorText,
            Response = response ?? new { }
        });
        return resp;
    }
}
internal static class ProfileJsonHelper
{
    public static bool TryParse(string json, out JsonDocument doc, out string error)
    {
        try
        {
            doc = JsonDocument.Parse(json);
            error = null;
            return true;
        }
        catch (JsonException ex)
        {
            doc = null;
            error = ex.Message;
            return false;
        }
    }
    public static string ComputeSignature(string json)
    {
        var hash = SHA256.HashData(Encoding.UTF8.GetBytes(json));
        return Convert.ToHexString(hash);
    }
}
#endregion
#region GetPhoneProfile
public class GetPhoneProfile
{
    private readonly ILogger<GetPhoneProfile> _logger;
    public GetPhoneProfile(ILogger<GetPhoneProfile> logger)
    {
        _logger = logger;
    }
    [Function("GetPhoneProfile")]
    public async Task<HttpResponseData> Run([HttpTrigger(AuthorizationLevel.Anonymous, "get")] HttpRequestData req)
    {
        var query = System.Web.HttpUtility.ParseQueryString(req.Url.Query);
        string cmeId = query["cme_id"];
        string clientSignature = query["signature"];
        if (string.IsNullOrWhiteSpace(cmeId))
            return await HttpJson.WriteAsync(req, HttpStatusCode.OK, 1, "Missing cme_id");
        try
        {
            using var conn = new SqlConnection(Environment.GetEnvironmentVariable("SqlConnectionString"));
            await conn.OpenAsync();
            using var cmd = new SqlCommand(@"
                SELECT profile_json, profile_signature
                FROM tblPhoneProfiles
                WHERE cme_id = @cme_id
            ", conn);
            cmd.Parameters.Add("@cme_id", SqlDbType.VarChar, 20).Value = cmeId;
            using var reader = await cmd.ExecuteReaderAsync();
            if (!await reader.ReadAsync())
                return await HttpJson.WriteAsync(req, HttpStatusCode.OK, 2, "Profile not found");
            string profileJson = reader.GetString(0);
            string profileSignature = reader.GetString(1);
            if (!string.IsNullOrWhiteSpace(clientSignature) && string.Equals(clientSignature, profileSignature, StringComparison.OrdinalIgnoreCase))
            {
                return await HttpJson.WriteAsync(req, HttpStatusCode.OK, 0, "Up to date");
            }
            if (!ProfileJsonHelper.TryParse(profileJson, out var jsonDoc, out var error))
            {
                _logger.LogError("Invalid profile JSON for {cmeId}: {error}", cmeId, error);
                return await HttpJson.WriteAsync(req, HttpStatusCode.OK, 3, "Invalid profile JSON");
            }
            using (jsonDoc)
            {
                return await HttpJson.WriteAsync(req, HttpStatusCode.OK, 0, "", new
                {
                    Signature = profileSignature,
                    Profile = jsonDoc.RootElement
                });
            }
        }
        catch (Exception ex)
        {
            _logger.LogError(ex, "GetPhoneProfile failed");
            return await HttpJson.WriteAsync(req, HttpStatusCode.OK, 3, "Server error");
        }
    }
}
#endregion
#region UploadPhoneProfile
public class UploadPhoneProfile
{
    private readonly ILogger<UploadPhoneProfile> _logger;
    public UploadPhoneProfile(ILogger<UploadPhoneProfile> logger)
    {
        _logger = logger;
    }
    [Function("UploadPhoneProfile")]
    public async Task<HttpResponseData> Run([HttpTrigger(AuthorizationLevel.Anonymous, "post")] HttpRequestData req)
    {
        try
        {
            string body = await new StreamReader(req.Body).ReadToEndAsync();
            if (string.IsNullOrWhiteSpace(body))
                return await HttpJson.WriteAsync(req, HttpStatusCode.OK, 1, "Empty request body");
            using var doc = JsonDocument.Parse(body);
            var root = doc.RootElement;
            string cmeId = root.GetProperty("cme_id").GetString();
            string profileName = root.GetProperty("profile_name").GetString();
            string companyId = root.GetProperty("company_id").GetString();
            var profileElement = root.GetProperty("profile");
            string profileJson = profileElement.GetRawText();
            if (!ProfileJsonHelper.TryParse(profileJson, out _, out var error))
                return await HttpJson.WriteAsync(req, HttpStatusCode.OK, 2, $"Invalid profile JSON: {error}");
            string signature = ProfileJsonHelper.ComputeSignature(profileJson);
            using var conn = new SqlConnection(Environment.GetEnvironmentVariable("SqlConnectionString"));
            await conn.OpenAsync();
            using var cmd = new SqlCommand(@"
                MERGE tblPhoneProfiles AS t
                USING (SELECT @cme_id AS cme_id) s
                ON t.cme_id = s.cme_id
                WHEN MATCHED THEN
                    UPDATE SET
                        profile_json = @profile_json,
                        profile_signature = @profile_signature,
                        profile_name = @profile_name,
                        company_id = @company_id
                WHEN NOT MATCHED THEN
                    INSERT (cme_id, profile_json, profile_signature, profile_name, company_id)
                    VALUES (@cme_id, @profile_json, @profile_signature, @profile_name, @company_id);
            ", conn);
            cmd.Parameters.AddWithValue("@cme_id", cmeId);
            cmd.Parameters.AddWithValue("@profile_json", profileJson);
            cmd.Parameters.AddWithValue("@profile_signature", signature);
            cmd.Parameters.AddWithValue("@profile_name", profileName);
            cmd.Parameters.AddWithValue("@company_id", companyId);
            await cmd.ExecuteNonQueryAsync();
            return await HttpJson.WriteAsync(req, HttpStatusCode.OK, 0, "", new
            {
                Signature = signature
            });
        }
        catch (Exception ex)
        {
            _logger.LogError(ex, "UploadPhoneProfile failed");
            return await HttpJson.WriteAsync(req, HttpStatusCode.OK, 3, "Server error");
        }
    }
}
#endregion