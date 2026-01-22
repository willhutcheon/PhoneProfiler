using Azure.Storage.Blobs;
using Microsoft.AspNetCore.Http;
using Microsoft.AspNetCore.Mvc;
using Microsoft.Azure.Functions.Worker;
using Microsoft.Azure.Functions.Worker.Http;
using Microsoft.Data.SqlClient;
using Microsoft.Extensions.Logging;
using System.Data;
using System.Net;
using System.Security.Cryptography.X509Certificates;
using System.Text.Json;
using System.Threading.Tasks;

namespace PhoneProfiler;

public static class ClientCertValidator
{
    public static X509Certificate2? GetClientCertificate(HttpRequestData req)
    {
        if (!req.Headers.TryGetValues("X-ARR-ClientCert", out var values))
            return null;
        string certBase64 = values.FirstOrDefault();
        if (string.IsNullOrEmpty(certBase64))
            return null;
        try
        {
            byte[] bytes = Convert.FromBase64String(certBase64);
            return new X509Certificate2(bytes);
        }
        catch
        {
            return null;
        }
    }
    public static bool IsCertificateAllowed(X509Certificate2 cert, ILogger logger)
    {
        var allowedThumbprints = Environment
            .GetEnvironmentVariable("AllowedClientThumbprints")?
            .Split(',', StringSplitOptions.RemoveEmptyEntries)
            .Select(t => t.Trim().ToUpperInvariant())
            .ToList();
        if (allowedThumbprints == null || allowedThumbprints.Count == 0)
        {
            logger.LogWarning("No allowed thumbprints configured.");
            return false;
        }
        string incoming = cert.Thumbprint?.ToUpperInvariant() ?? "";
        logger.LogInformation($"Client cert thumbprint = {incoming}");
        return allowedThumbprints.Contains(incoming);
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
        _logger.LogInformation("CheckPhoneUpdate request received.");
        // Certificate validation
        var cert = ClientCertValidator.GetClientCertificate(req);
        if (cert == null)
        {
            var resp = req.CreateResponse(HttpStatusCode.Unauthorized);
            await resp.WriteStringAsync("Client certificate missing.");
            return resp;
        }
        if (!ClientCertValidator.IsCertificateAllowed(cert, _logger))
        {
            var resp = req.CreateResponse(HttpStatusCode.Unauthorized);
            await resp.WriteStringAsync("Invalid client certificate.");
            return resp;
        }
        var query = System.Web.HttpUtility.ParseQueryString(req.Url.Query);
        string serialNumber = query["serialNumber"];
        string phoneVersion = query["phoneVersion"];
        if (string.IsNullOrWhiteSpace(serialNumber) || string.IsNullOrWhiteSpace(phoneVersion))
        {
            return await CreateJsonResponse(req, 1, "Missing parameters", null);
        }
        try
        {
            string connString = Environment.GetEnvironmentVariable("SqlConnectionString");
            using var conn = new SqlConnection(connString);
            await conn.OpenAsync();
            string sql = @"
                SELECT 
                    target_phone_version,
                    target_phone_filename,
                    update_type
                FROM tblPhoneDevices
                WHERE serial_number_hardware = @serial
                ";
            using var cmd = new SqlCommand(sql, conn);
            cmd.Parameters.AddWithValue("@serial", serialNumber);
            using var reader = await cmd.ExecuteReaderAsync();
            if (!reader.HasRows)
            {
                return await CreateJsonResponse(req, 1, "invalid serial number", null);
            }
            await reader.ReadAsync();
            string targetVersion = reader["target_phone_version"]?.ToString();
            string targetFilename = reader["target_phone_filename"]?.ToString();
            string updateType = reader["update_type"]?.ToString();
            if (!string.Equals(phoneVersion, targetVersion, StringComparison.OrdinalIgnoreCase))
            {
                var responseObj = new
                {
                    Filename = targetFilename,
                    Signature = "0",
                    UpdateType = updateType
                };
                return await CreateJsonResponse(req, 0, "", responseObj);
            }
            // Otherwise device is already up to date
            return await CreateJsonResponse(req, 2, "up to date", null);
        }
        catch (Exception ex)
        {
            _logger.LogError(ex, "Database error in CheckPhoneUpdate.");
            return await CreateJsonResponse(req, 2, "Server error", null);
        }
    }
    // Helper to build JSON response
    private async Task<HttpResponseData> CreateJsonResponse(HttpRequestData req, int errorCode, string errorText, object response)
    {
        var resp = req.CreateResponse(HttpStatusCode.OK);
        // Build payload
        var payload = new
        {
            ErrorCode = errorCode,
            ErrorText = errorText,
            Response = response ?? new { },
        };
        // Serialize manually
        string jsonString = JsonSerializer.Serialize(payload);
        // Convert to bytes to set Content-Length
        byte[] bytes = System.Text.Encoding.UTF8.GetBytes(jsonString);
        // Set headers (NO CHUNKING)
        resp.Headers.Add("Content-Type", "application/json");
        resp.Headers.Add("Content-Length", bytes.Length.ToString());
        // Write body
        await resp.Body.WriteAsync(bytes, 0, bytes.Length);
        return resp;
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
        _logger.LogInformation("UploadPhoneProfile request received.");
        // Certificate validation
        var cert = ClientCertValidator.GetClientCertificate(req);
        if (cert == null)
        {
            var resp = req.CreateResponse(HttpStatusCode.Unauthorized);
            await resp.WriteStringAsync("Client certificate missing.");
            return resp;
        }
        if (!ClientCertValidator.IsCertificateAllowed(cert, _logger))
        {
            var resp = req.CreateResponse(HttpStatusCode.Unauthorized);
            await resp.WriteStringAsync("Invalid client certificate.");
            return resp;
        }
        try
        {
            string body = await new StreamReader(req.Body).ReadToEndAsync();
            if (string.IsNullOrWhiteSpace(body))
                return await CreateJsonResponse(req, 1, "Empty request body", null);
            using var doc = JsonDocument.Parse(body);
            var root = doc.RootElement;
            // Required fields
            string publishDataTo = root.GetProperty("publish_data_to").GetString();
            string surveyDomain = root.GetProperty("survey_domain").GetString();
            using var conn = new SqlConnection(Environment.GetEnvironmentVariable("SqlConnectionString"));
            await conn.OpenAsync();
            using var cmd = new SqlCommand(@"
                INSERT INTO tblPhoneProfiles (
                    publish_data_to,
                    survey_domain
                )
                VALUES (
                    @publish_data_to,
                    @survey_domain
                )", conn);
            cmd.Parameters.AddWithValue("@publish_data_to", publishDataTo);
            cmd.Parameters.AddWithValue("@survey_domain", surveyDomain);
            await cmd.ExecuteNonQueryAsync();
            return await CreateJsonResponse(req, 0, "", new
            {
                Message = "Profile stored successfully"
            });
        }
        catch (JsonException)
        {
            return await CreateJsonResponse(req, 2, "Invalid JSON format", null);
        }
        catch (Exception ex)
        {
            _logger.LogError(ex, "UploadPhoneProfile failed.");
            return await CreateJsonResponse(req, 3, "Server error", null);
        }
    }
    private async Task<HttpResponseData> CreateJsonResponse(HttpRequestData req, int errorCode, string errorText, object response)
    {
        var resp = req.CreateResponse(HttpStatusCode.OK);
        var payload = new
        {
            ErrorCode = errorCode,
            ErrorText = errorText,
            Response = response ?? new { }
        };
        string json = JsonSerializer.Serialize(payload);
        byte[] bytes = System.Text.Encoding.UTF8.GetBytes(json);
        resp.Headers.Add("Content-Type", "application/json");
        resp.Headers.Add("Content-Length", bytes.Length.ToString());
        await resp.Body.WriteAsync(bytes, 0, bytes.Length);
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
    public async Task<HttpResponseData> Run(
        [HttpTrigger(AuthorizationLevel.Anonymous, "get")]
        HttpRequestData req)
    {
        _logger.LogInformation("GetPhoneProfile request received.");
        // --- Client certificate validation ---
        var cert = ClientCertValidator.GetClientCertificate(req);
        if (cert == null)
        {
            var resp = req.CreateResponse(HttpStatusCode.Unauthorized);
            await resp.WriteStringAsync("Client certificate missing.");
            return resp;
        }
        if (!ClientCertValidator.IsCertificateAllowed(cert, _logger))
        {
            var resp = req.CreateResponse(HttpStatusCode.Unauthorized);
            await resp.WriteStringAsync("Invalid client certificate.");
            return resp;
        }
        var query = System.Web.HttpUtility.ParseQueryString(req.Url.Query);
        string serial = query["serial"];
        string clientSignature = query["signature"];
        if (string.IsNullOrWhiteSpace(serial))
        {
            return await CreateJsonResponse(req, 1, "Missing serial parameter", null);
        }
        try
        {
            using var conn = new SqlConnection(Environment.GetEnvironmentVariable("SqlConnectionString"));
            await conn.OpenAsync();
            using var deviceCmd = new SqlCommand(@"
                SELECT profile_id
                FROM tblPhoneDevices
                WHERE serial_number_hardware = @serial
            ", conn);
            deviceCmd.Parameters.AddWithValue("@serial", serial);
            var profileIdObj = await deviceCmd.ExecuteScalarAsync();
            if (profileIdObj == null || profileIdObj == DBNull.Value)
            {
                return await CreateJsonResponse(req, 2, "No profile assigned", null);
            }
            int profileId = Convert.ToInt32(profileIdObj);
            using var profileCmd = new SqlCommand(@"
                SELECT profile_json, profile_signature
                FROM tblPhoneProfiles
                WHERE cme_id = @id
            ", conn);
            profileCmd.Parameters.AddWithValue("@id", profileId);
            using var reader = await profileCmd.ExecuteReaderAsync();
            if (!await reader.ReadAsync())
            {
                return await CreateJsonResponse(req, 2, "Profile not found", null);
            }
            string storedSignature = reader["profile_signature"]?.ToString();
            string storedJson = reader["profile_json"]?.ToString();
            if (string.IsNullOrWhiteSpace(storedJson) || string.IsNullOrWhiteSpace(storedSignature))
            {
                return await CreateJsonResponse(req, 3, "Invalid profile data", null);
            }
            if (!string.IsNullOrWhiteSpace(clientSignature) && string.Equals(clientSignature, storedSignature, StringComparison.OrdinalIgnoreCase))
            {
                // Device already has latest profile
                return await CreateJsonResponse(req, 0, "Up to date", null);
            }
            using var jsonDoc = JsonDocument.Parse(storedJson);
            return await CreateJsonResponse(req, 0, "", new
            {
                Signature = storedSignature,
                Profile = jsonDoc.RootElement
            });
        }
        catch (Exception ex)
        {
            _logger.LogError(ex, "GetPhoneProfile failed.");
            return await CreateJsonResponse(req, 3, "Server error", null);
        }
    }
    private async Task<HttpResponseData> CreateJsonResponse(HttpRequestData req, int errorCode, string errorText, object response)
    {
        var resp = req.CreateResponse(HttpStatusCode.OK);
        var payload = new
        {
            ErrorCode = errorCode,
            ErrorText = errorText,
            Response = response ?? new { }
        };
        string json = JsonSerializer.Serialize(payload);
        byte[] bytes = System.Text.Encoding.UTF8.GetBytes(json);
        resp.Headers.Add("Content-Type", "application/json");
        resp.Headers.Add("Content-Length", bytes.Length.ToString());
        await resp.Body.WriteAsync(bytes, 0, bytes.Length);
        return resp;
    }
}