using Microsoft.Azure.Functions.Worker;
using Microsoft.Azure.Functions.Worker.Http;
using Microsoft.Data.SqlClient;
using Microsoft.Extensions.Logging;
using System.Data;
using System.Net;
using System.Text.Json;

internal static class HttpJson
{
    public static async Task<HttpResponseData> WriteAsync(HttpRequestData req, HttpStatusCode status, int errorCode, string errorText, object response)
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
        {
            return await HttpJson.WriteAsync(req, HttpStatusCode.OK, 1, "Missing cme_id", null);
        }
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
            {
                return await HttpJson.WriteAsync(req, HttpStatusCode.OK, 2, "Profile not found", null);
            }
            string profileJson = reader.GetString(0);
            string profileSignature = reader.GetString(1);
            if (!string.IsNullOrWhiteSpace(clientSignature) && string.Equals(clientSignature, profileSignature, StringComparison.OrdinalIgnoreCase))
            {
                return await HttpJson.WriteAsync(req, HttpStatusCode.OK, 0, "Up to date", null);
            }
            using var jsonDoc = JsonDocument.Parse(profileJson);
            return await HttpJson.WriteAsync(req, HttpStatusCode.OK, 0, "", new
            {
                Signature = profileSignature,
                Profile = jsonDoc.RootElement
            });
        }
        catch (Exception ex)
        {
            _logger.LogError(ex, "GetPhoneProfile failed");
            return await HttpJson.WriteAsync(req, HttpStatusCode.OK, 3, "Server error", null);
        }
    }
}
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
                return await HttpJson.WriteAsync(req, HttpStatusCode.OK, 1, "Empty request body", null);
            using var doc = JsonDocument.Parse(body);
            var root = doc.RootElement;
            string cmeId = root.GetProperty("cme_id").GetString();
            string publishDataTo = root.GetProperty("publish_data_to").GetString();
            string surveyDomain = root.GetProperty("survey_domain").GetString();
            string profileName = root.GetProperty("profile_name").GetString();
            string companyId = root.GetProperty("company_id").GetString();
            JsonElement profile = root.GetProperty("profile");
            string profileJson = profile.GetRawText();
            string signature = Convert.ToHexString(
                System.Security.Cryptography.SHA256.HashData(System.Text.Encoding.UTF8.GetBytes(profileJson))
            );
            using var conn = new SqlConnection(Environment.GetEnvironmentVariable("SqlConnectionString"));
            await conn.OpenAsync();
            using var cmd = new SqlCommand(@"
                MERGE tblPhoneProfiles AS t
                USING (SELECT @cme_id AS cme_id) s
                ON t.cme_id = s.cme_id
                WHEN MATCHED THEN
                    UPDATE SET
                        publish_data_to = @publish_data_to,
                        survey_domain = @survey_domain,
                        profile_json = @profile_json,
                        profile_signature = @profile_signature,
                        profile_name = @profile_name,
                        company_id = @company_id
                WHEN NOT MATCHED THEN
                    INSERT (
                        cme_id,
                        publish_data_to,
                        survey_domain,
                        profile_json,
                        profile_signature,
                        profile_name,
                        company_id
                    )
                    VALUES (
                        @cme_id,
                        @publish_data_to,
                        @survey_domain,
                        @profile_json,
                        @profile_signature,
                        @profile_name,
                        @company_id
                    );
            ", conn);
            cmd.Parameters.AddWithValue("@cme_id", cmeId);
            cmd.Parameters.AddWithValue("@publish_data_to", publishDataTo);
            cmd.Parameters.AddWithValue("@survey_domain", surveyDomain);
            cmd.Parameters.AddWithValue("@profile_json", profileJson);
            cmd.Parameters.AddWithValue("@profile_signature", signature);
            cmd.Parameters.AddWithValue("@profile_name", profileName);
            cmd.Parameters.AddWithValue("@company_id", companyId);
            await cmd.ExecuteNonQueryAsync();
            return await HttpJson.WriteAsync(req, HttpStatusCode.OK, 0, "", new { Signature = signature });
        }
        catch (Exception ex)
        {
            _logger.LogError(ex, "UploadPhoneProfile failed");
            return await HttpJson.WriteAsync(req, HttpStatusCode.OK, 3, "Server error", null);
        }
    }
}
public class CheckPhoneUpdate
{
    private readonly ILogger<CheckPhoneUpdate> _logger;
    public CheckPhoneUpdate(ILogger<CheckPhoneUpdate> logger)
    {
        _logger = logger;
    }
    [Function("CheckPhoneUpdate")]
    public async Task<HttpResponseData> Run([HttpTrigger(AuthorizationLevel.Anonymous, "get")] HttpRequestData req)
    {
        var query = System.Web.HttpUtility.ParseQueryString(req.Url.Query);
        string serial = query["serialNumber"];
        string phoneVersion = query["phoneVersion"];
        if (string.IsNullOrWhiteSpace(serial) || string.IsNullOrWhiteSpace(phoneVersion))
        {
            return await HttpJson.WriteAsync(req, HttpStatusCode.OK, 1, "Missing parameters", null);
        }
        try
        {
            using var conn = new SqlConnection(Environment.GetEnvironmentVariable("SqlConnectionString"));
            await conn.OpenAsync();
            using var cmd = new SqlCommand(@"
                SELECT phone_model, status, company_id, tags
                FROM tblPhoneDevices
                WHERE cme_id = @cme_id
            ", conn);
            cmd.Parameters.AddWithValue("@cme_id", serial);
            using var reader = await cmd.ExecuteReaderAsync();
            if (!await reader.ReadAsync())
            {
                return await HttpJson.WriteAsync(req, HttpStatusCode.OK, 1, "Invalid cme_id", null);
            }
            string phoneModel = reader.GetString(0);
            string status = reader.IsDBNull(1) ? null : reader.GetString(1);
            string companyId = reader.IsDBNull(2) ? null : reader.GetString(2);
            string tags = reader.IsDBNull(3) ? null : reader.GetString(3);
            return await HttpJson.WriteAsync(req, HttpStatusCode.OK, 0, "", new
            {
                PhoneModel = phoneModel,
                Status = status,
                CompanyId = companyId,
                Tags = tags
            });
        }
        catch (Exception ex)
        {
            _logger.LogError(ex, "CheckPhoneUpdate failed");
            return await HttpJson.WriteAsync(req, HttpStatusCode.OK, 3, "Server error", null);
        }
    }
}
