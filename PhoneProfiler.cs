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

public class PhoneProfiler
{
    private readonly ILogger<PhoneProfiler> _logger;

    public PhoneProfiler(ILogger<PhoneProfiler> logger)
    {
        _logger = logger;
    }

    [Function("Function1")]
    public IActionResult Run([HttpTrigger(AuthorizationLevel.Function, "get", "post")] HttpRequest req)
    {
        _logger.LogInformation("C# HTTP trigger function processed a request.");
        return new OkObjectResult("Welcome to Azure Functions!");
    }
}










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