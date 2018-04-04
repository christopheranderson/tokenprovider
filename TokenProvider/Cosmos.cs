using System.Linq;
using System.Net;
using System.Net.Http;
using System.Threading.Tasks;
using Microsoft.Azure.WebJobs;
using Microsoft.Azure.WebJobs.Extensions.Http;
using Microsoft.Azure.WebJobs.Host;
using CosmosDBResourceTokenProvider;
using System.IdentityModel.Tokens.Jwt;
using System.Security.Claims;
using System;
using Microsoft.Azure.Documents;
using Microsoft.Azure.Documents.Client;
using System.Collections.Generic;

namespace TokenProvider
{
    public static class Cosmos
    {
        private static ResourceTokenProvider resourceTokenProvider = ResourceTokenProvider.GetDefault();
        private static Dictionary<string, List<AppPermission>> RolePermissionsMap = CreateDefaultRolePermissionMap(); // TODO: Right now, only support 1 default role


        [FunctionName("Cosmos_TokenProvider")]
        public static async Task<HttpResponseMessage> Run([HttpTrigger(AuthorizationLevel.Anonymous, "get", "post", Route = "cosmos/token")]HttpRequestMessage req, TraceWriter log, ExecutionContext context)
        {
            string userId;
            JwtSecurityToken parsedToken;
            try
            {
                var token = req.Headers.First(h => h.Key == "token").Value.First() ?? throw new InvalidOperationException();
                parsedToken = new JwtSecurityToken(token) ?? throw new InvalidOperationException();
                userId = Cosmos.getUserId(parsedToken) ?? throw new InvalidOperationException();
            }
            catch (Exception e)
            {
                log.Error($"Authentication issue", e);
                return req.CreateErrorResponse(HttpStatusCode.Unauthorized, "Missing or invalid auth token. Reference {context.InvocationId} for details.");
            }

            List<PermissionToken> permissionTokens = new List<PermissionToken>();

            var role = "Default"; // TODO: make this able to be added from claim
            try
            {
                foreach (AppPermission p in RolePermissionsMap[role])
                {
                    var partitionKey = parsedToken.Claims.Where(c => c.Type == p.partitionKeyPropertyName).FirstOrDefault();
                    PermissionToken permissionToken = await resourceTokenProvider.GetToken(p.DatabaseId, new Uri(p.ResourceId, UriKind.Relative), role, p.PermissionMode, partitionKey == null ? null : new PartitionKey(partitionKey));
                    log.Info($"User[{userId}] assigned token[{permissionToken.Id}] in role[{role}] with permissions(resource[{p.ResourceId}], PermissionMode[{(p.PermissionMode == PermissionMode.All ? "ALL" : "READ/")}{(partitionKey != null ? $", {partitionKey}" : "")}");
                    permissionTokens.Add(permissionToken);
                }
                return req.CreateResponse(permissionTokens);
            }
            catch (Exception e)
            {
                log.Error($"Could not create token for user[{userId}]", e);
                return req.CreateErrorResponse(HttpStatusCode.InternalServerError, $"Server error. Reference {context.InvocationId} for details.");
            }
        }

        private static string getUserId(JwtSecurityToken jwtToken)
        {
            // This only works for AAD for now...
            return jwtToken.Claims.First(c => c.Type == "upn").Value;
        }

        private static Dictionary<string, List<AppPermission>> CreateDefaultRolePermissionMap()
        {
            var d = new Dictionary<string, List<AppPermission>>();
            var l = new List<AppPermission>();
            var n = "Default";

            // Handle single value case
            string value = Environment.GetEnvironmentVariable("TOKEN_PROVIDER_COSMOS_DEFAULT");
            if (!string.IsNullOrEmpty(value))
            {
                l.Add(AppPermission.ParseFromString(value));
            }

            // Handle multiple value case
            string keysString = Environment.GetEnvironmentVariable("TOKEN_PROVIDER_COSMOS_DEFAULT_KEYS");
            if (!string.IsNullOrEmpty(keysString))
            {
                string[] keys = keysString.Split(';');
                foreach (string key in keys)
                {
                    l.Add(AppPermission.ParseFromString(key));
                }
            }

            d.Add(n, l);
            return d;
        }
    }

    public class AppPermission
    {
        public string ResourceId { get; set; }
        public string DatabaseId { get; set; }
        public string partitionKeyPropertyName { get; set; }
        public PermissionMode PermissionMode { get; set; }

        public static AppPermission ParseFromString(string permissionString)
        {
            var p = new AppPermission();
            // String format: path/to/resource[(partitionKey)][{permission}]
            var databaseSectionStart = permissionString.IndexOf("/");
            var databaseSectionEnd = permissionString.IndexOf("/", databaseSectionStart + 1);
            var partitionKeySectionTokenStart = permissionString.IndexOf('(');
            var partitionKeySectionTokenEnd = permissionString.IndexOf(')');
            var permissionSectionStart = permissionString.IndexOf('{');
            var permissionSectionEnd = permissionString.IndexOf('}');
            var resourceSectionEnd = partitionKeySectionTokenStart >= 0 ? partitionKeySectionTokenStart : permissionSectionStart >= 0 ? permissionSectionStart : permissionString.Length - 1;

            p.ResourceId = permissionString.Substring(0, resourceSectionEnd);

            // This should always be true, but just in case there is a bad string, just ignore it here
            if (databaseSectionStart >= 0 && databaseSectionEnd >= databaseSectionStart)
            {
                p.DatabaseId = permissionString.Substring(databaseSectionStart + 1, databaseSectionEnd - (databaseSectionStart + 1));
            }

            if (partitionKeySectionTokenStart >= 0 && partitionKeySectionTokenEnd > partitionKeySectionTokenStart)
            {
                p.ResourceId = permissionString.Substring(partitionKeySectionTokenStart + 1, partitionKeySectionTokenEnd - (partitionKeySectionTokenStart + 1));
            }

            if (permissionSectionStart >= 0 && permissionSectionEnd > permissionSectionStart)
            {
                var permissionModeString = permissionString.Substring(permissionSectionStart + 1, permissionSectionEnd - (permissionSectionStart + 1));
                p.PermissionMode = permissionModeString == "All" ? PermissionMode.All : PermissionMode.Read;
            }

            return p;
        }
    }
}
