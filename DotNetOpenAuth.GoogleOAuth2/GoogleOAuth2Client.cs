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
        /// The token info endpoint.
        /// </summary>
        private const string TOKEN_INFO_ENDPOINT = "https://www.googleapis.com/oauth2/v1/tokeninfo";

        /// <summary>
        /// The user info endpoint.
        /// </summary>
        private const string UserInfoEndpoint = "https://www.googleapis.com/oauth2/v1/userinfo";

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
            : this(clientId, clientSecret, new[] { "profile", "email" }) { }

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
            var scopes = _requestedScopes;
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
            var uri = BuildUri(UserInfoEndpoint);

            var webRequest = (HttpWebRequest) WebRequest.Create(uri);
            webRequest.Headers.Add(HttpRequestHeader.Authorization, "Bearer " + accessToken);

            using (var webResponse = webRequest.GetResponse())
            using (var stream = webResponse.GetResponseStream())
            {
                if (stream == null)
                    return null;

                using (var textReader = new StreamReader(stream))
                {
                    var json = textReader.ReadToEnd();
                    var extraData = JsonConvert.DeserializeObject<Dictionary<string, string>>(json);
                    return extraData;
                }
            }
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

        private Uri BuildUri(string baseUri, NameValueCollection queryParameters = null)
        {
            UriBuilder builder;

            //baseUri = string.Format(baseUri, string.IsNullOrWhiteSpace(_apiVersion) ? string.Empty : _apiVersion + "/");

            if (queryParameters != null)
            {
                var keyValuePairs = queryParameters.AllKeys.Select(k => HttpUtility.UrlEncode(k) + "=" + HttpUtility.UrlEncode(queryParameters[k]));
                var qs = String.Join("&", keyValuePairs);

                builder = new UriBuilder(baseUri) { Query = qs };
            }
            else
            {
                builder = new UriBuilder(baseUri);
            }
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

        /// <summary>
        /// Verifies whether provided access token is really issued for specified application.
        /// </summary>
        /// <param name="accessToken">Access token.</param>
        /// <returns></returns>
        /// <exception cref="System.Exception">Throws exception when dynamic data object does not contain app_id or is_valid attributes.</exception>
        public bool VerifyAccessToken(string accessToken)
        {
            bool ret = false;

            var uri = BuildUri(TOKEN_INFO_ENDPOINT, new NameValueCollection
                {
                    { "access_token", accessToken },
                });

            var webRequest = (HttpWebRequest)WebRequest.Create(uri);

            try
            {
                using (var webResponse = (HttpWebResponse)webRequest.GetResponse())
                {
                    var responseStream = webResponse.GetResponseStream();
                    if (responseStream != null)
                    {
                        using (var reader = new StreamReader(responseStream))
                        {
                            var json = reader.ReadToEnd();
                            dynamic responseData = JsonConvert.DeserializeObject<dynamic>(json);

                            try
                            {
                                if (responseData.audience == _clientId)
                                {
                                    ret = true;
                                }
                            }
                            catch (Exception ex)
                            {
                                throw new Exception("Cannot verify access token. See inner exception.", ex);
                            }
                        }
                    }
                }
            }
            catch (Exception ex)
            {
                throw new Exception("Cannot verify access token. See inner exception.", ex);
            }

            return ret;
        }

        /// <summary>
        /// Verifies whether provided access token was really issued for specified application and checks it againts provided e-mail.
        /// </summary>
        /// <param name="accessToken"></param>
        /// <param name="email"></param>
        /// <returns></returns>
        /// <exception cref="System.Exception">Throws exception when dynamic data object does not contain app_id or is_valid attributes OR when downloaded user data does not contain email.</exception>
        public bool VerifyAccessToken(string accessToken, string email)
        {
            bool ret = false;

            try
            {
                if (VerifyAccessToken(accessToken))
                {
                    IDictionary<string, string> data = GetUserData(accessToken);
                    if (data != null)
                    {
                        ret = (data["email"] == email);
                    }
                }
            }
            catch (Exception ex)
            {
                throw new Exception("Cannot verify access token and e-mail. See inner exception.", ex);
            }

            return ret;
        }
    }
}
