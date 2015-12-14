using System;
using System.Collections.Generic;
using System.Collections.Specialized;
using System.IO;
using System.Linq;
using System.Net;
using System.Web;
using DotNetOpenAuth.AspNet.Clients;
using Newtonsoft.Json;
using Newtonsoft.Json.Linq;

namespace DotNetOpenAuth.GoogleOAuth2
{
    /// <summary>
    /// A DotNetOpenAuth client for logging in to Google using OAuth2.
    /// Reference: https://developers.google.com/accounts/docs/OAuth2
    /// </summary>
    public class GoogleOAuth2Client : OAuth2Client
    {
        #region Constants and Fields

        /// <summary>
        /// The authorization endpoint.
        /// </summary>
        private const string AuthorizationEndpoint = "https://accounts.google.com/o/oauth2/auth";

        /// <summary>
        /// The token endpoint.
        /// </summary>
        private const string TokenEndpoint = "https://accounts.google.com/o/oauth2/token";

        /// <summary>
        /// The user info endpoint.
        /// </summary>
        private const string UserInfoEndpoint = "https://www.googleapis.com/oauth2/v1/userinfo";

        /// <summary>
        /// The base uri for scopes.
        /// </summary>
        private const string ScopeBaseUri = "https://www.googleapis.com/auth/";

        /// <summary>
        /// The _app id.
        /// </summary>
        private readonly string _clientId;

        /// <summary>
        /// The _app secret.
        /// </summary>
        private readonly string _clientSecret;

        /// <summary>
        /// The requested scopes.
        /// </summary>
        private readonly string[] _requestedScopes;

        #endregion

        /// <summary>
        /// Creates a new Google OAuth2 Client, requesting the default "userinfo.profile" and "userinfo.email" scopes.
        /// </summary>
        /// <param name="clientId">The Google Client Id</param>
        /// <param name="clientSecret">The Google Client Secret</param>
        public GoogleOAuth2Client(string clientId, string clientSecret)
            : this(clientId, clientSecret, new[] { "userinfo.profile", "userinfo.email" }) { }

        /// <summary>
        /// Creates a new Google OAuth2 client.
        /// </summary>
        /// <param name="clientId">The Google Client Id</param>
        /// <param name="clientSecret">The Google Client Secret</param>
        /// <param name="requestedScopes">One or more requested scopes, passed without the base URI.</param>
        public GoogleOAuth2Client(string clientId, string clientSecret, params string[] requestedScopes)
            : base("google")
        {
            if (string.IsNullOrWhiteSpace(clientId))
                throw new ArgumentNullException("clientId");

            if (string.IsNullOrWhiteSpace(clientSecret))
                throw new ArgumentNullException("clientSecret");

            if (requestedScopes == null)
                throw new ArgumentNullException("requestedScopes");

            if (requestedScopes.Length == 0)
                throw new ArgumentException("One or more scopes must be requested.", "requestedScopes");

            _clientId = clientId;
            _clientSecret = clientSecret;
            _requestedScopes = requestedScopes;
        }

        protected override Uri GetServiceLoginUrl(Uri returnUrl)
        {
            var scopes = _requestedScopes.Select(x => !x.StartsWith("http", StringComparison.OrdinalIgnoreCase) ? ScopeBaseUri + x : x);
            var state = string.IsNullOrEmpty(returnUrl.Query) ? string.Empty : returnUrl.Query.Substring(1);

            return BuildUri(AuthorizationEndpoint, new NameValueCollection
                {
                    { "response_type", "code" },
                    { "client_id", _clientId },
                    { "scope", string.Join(" ", scopes) },
                    { "redirect_uri", returnUrl.GetLeftPart(UriPartial.Path) },
                    { "state", state },
                });
        }

        protected override IDictionary<string, string> GetUserData(string accessToken)
        {
            var uri = BuildUri(UserInfoEndpoint, new NameValueCollection { { "access_token", accessToken } });

            var webRequest = (HttpWebRequest) WebRequest.Create(uri);

            using (var webResponse = webRequest.GetResponse())
            using (var stream = webResponse.GetResponseStream())
            {
                if (stream == null)
                    return null;

                using (var textReader = new StreamReader(stream))
                {
                    var json = textReader.ReadToEnd();
                    var extraData = new Dictionary<string, string>();
                    try
                    {
                        extraData = JsonConvert.DeserializeObject<Dictionary<string, string>>(json);
                    }
                    catch (Exception ex)
                    {
                        // Perhaps the ReflectionPermission has not been enabled on the Web app;
                        // Try using an alternative method of parsing to convert the JSON into
                        // a Dictionary<string, string>:
                        extraData = JsonToDictionary(json);
                    }
                    return extraData;
                }
            }
        }

        protected Dictionary<string, string> JsonToDictionary(string json)
        {
            Dictionary<string, string> dictionary = new Dictionary<string, string>();
            int braceLoc1 = json.IndexOf("{", 0);
            if (braceLoc1 == -1)
                return dictionary;
            int braceLoc2 = json.IndexOf("}", braceLoc1);
            if (braceLoc2 == -1)
                return dictionary;
            string mainBlock = json.Substring(braceLoc1 + 1, braceLoc2 - braceLoc1 - 1);
            while (mainBlock.Length > 0)
            {
                int quoteLoc1 = mainBlock.IndexOf('\"', 0);
                if (quoteLoc1 == -1)
                    break;
                int quoteLoc2 = mainBlock.IndexOf('\"', quoteLoc1 + 1);
                if (quoteLoc2 == -1)
                    break;
                string key = mainBlock.Substring(quoteLoc1 + 1, quoteLoc2 - quoteLoc1 - 1);
                mainBlock = mainBlock.Substring(quoteLoc2 + 1);
                mainBlock = mainBlock.TrimStart(" :\r\n\t".ToCharArray());
                if (mainBlock.StartsWith("\""))// Has quotation marks on value;
                {
                    quoteLoc1 = mainBlock.IndexOf('\"', 0);
                    if (quoteLoc1 == -1)
                        break;
                    quoteLoc2 = mainBlock.IndexOf('\"', quoteLoc1 + 1);
                    if (quoteLoc2 == -1)
                        break;
                    string value = mainBlock.Substring(quoteLoc1 + 1, quoteLoc2 - quoteLoc1 - 1);
                    dictionary.Add(key, value);
                    mainBlock = mainBlock.Substring(quoteLoc2 + 1);
                }
                else// Has bare value (no quotation marks);
                {
                    int commaLoc = mainBlock.IndexOf(',', 0);
                    if (commaLoc == -1)
                        commaLoc = mainBlock.Length;
                    string value = mainBlock.Substring(0, commaLoc).Trim(" \r\n\t".ToCharArray());
                    dictionary.Add(key, value);
                    mainBlock = mainBlock.Substring(commaLoc);
                }
            }
            return dictionary;
        }

        protected override string QueryAccessToken(Uri returnUrl, string authorizationCode)
        {
            var postData = HttpUtility.ParseQueryString(string.Empty);
            postData.Add(new NameValueCollection
                {
                    { "grant_type", "authorization_code" },
                    { "code", authorizationCode },
                    { "client_id", _clientId },
                    { "client_secret", _clientSecret },
                    { "redirect_uri", returnUrl.GetLeftPart(UriPartial.Path) },
                });

            var webRequest = (HttpWebRequest) WebRequest.Create(TokenEndpoint);

            webRequest.Method = "POST";
            webRequest.ContentType = "application/x-www-form-urlencoded";

            using (var s = webRequest.GetRequestStream())
            using (var sw = new StreamWriter(s))
                sw.Write(postData.ToString());

            using (var webResponse = webRequest.GetResponse())
            {
                var responseStream = webResponse.GetResponseStream();
                if (responseStream == null)
                    return null;

                using (var reader = new StreamReader(responseStream))
                {
                    var response = reader.ReadToEnd();
                    var json = JObject.Parse(response);
                    var accessToken = json.Value<string>("access_token");
                    return accessToken;
                }
            }
        }

        private static Uri BuildUri(string baseUri, NameValueCollection queryParameters)
        {
            var keyValuePairs = queryParameters.AllKeys.Select(k => HttpUtility.UrlEncode(k) + "=" + HttpUtility.UrlEncode(queryParameters[k]));
            var qs = String.Join("&", keyValuePairs);

            var builder = new UriBuilder(baseUri) { Query = qs };
            return builder.Uri;
        }

        /// <summary>
        /// Google requires that all return data be packed into a "state" parameter.
        /// This should be called before verifying the request, so that the url is rewritten to support this.
        /// </summary>
        public static void RewriteRequest()
        {
            var ctx = HttpContext.Current;

            var stateString = HttpUtility.UrlDecode(ctx.Request.QueryString["state"]);
            if (stateString == null || !stateString.Contains("__provider__=google"))
                return;

            var q = HttpUtility.ParseQueryString(stateString);
            q.Add(ctx.Request.QueryString);
            q.Remove("state");

            ctx.RewritePath(ctx.Request.Path + "?" + q);
        }
    }
}
