DotNetOpenAuth OAuth2 Client for Google
======================================

DNOA and OAuthWebSecurity currently ship with only an OpenId provider for Google.
This is an OAuth2 client that you can use instead.

## Setup

 1. Setup your Google App using the [Google APIs console](https://code.google.com/apis/console).
    Detailed instructions [here](http://ben.onfabrik.com/posts/oauth-providers#google)

 2. Install this library from [NuGet](https://nuget.org/packages/DotNetOpenAuth.GoogleOAuth2), or compile from source and reference.

 3. Register the client instead of the existing Google OpenId client.

        var client = new GoogleOAuth2Client("yourClientId", "yourClientSecret");
        var extraData = new Dictionary<string, object>();
        OAuthWebSecurity.RegisterClient(client, "Google", extraData);

## Usage

Just like any other `OAuthWebSecurity` client, except you need one extra hook:

        // add this line
        GoogleOAuth2Client.RewriteRequest();

        // it belongs right before your existing call to
        OAuthWebSecurity.VerifyAuthentication(....)

This is needed because Google requires that any extra querystring parameters for the
redirect be packed into a single parameter called `state`.  Since `OAuthWebSecurity` needs
two parameters, `__provider__` and `__sid__` - we have to rewrite the url.

Reference: https://developers.google.com/accounts/docs/OAuth2


## Disclaimer

I don't work for Google, Microsoft, or DNOA.  This is released under the [MIT](LICENCE.txt) licence.  Do what you want with it.
