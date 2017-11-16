using System;
using System.IO;
using System.Net;
using System.Security.Cryptography;
using System.Web.Mvc;
using DotNetAuth.OAuth1a;
using RestSharp;
using WebApplication3.Providers;

namespace WebApplication3.Controllers
{
    public class JiraConnectController : Controller
    {
        private ApplicationCredentials JiraApplicationCredentials;
        private JIRAOAuth1aProvider JiraOAuth1AProvider;
        private OAuth10aStateManager OAuth10AStateManager;
        readonly HMACSHA1 sigHasher;

        public JiraConnectController()
        {
            var consumerSecret = "MIIEvQIBADANBgkqhkiG9w0BAQEFAASCBKcwggSjAgEAAoIBAQCmoGNjGeQmpAWjwAbMhPJRj+VW84iN7ZR4LF+FbiCxTw2eIVK5kSXQENZoCDHA0GOGDKhkCUJuxwS7+TLBSMG1PRjPqAWQTuC3FvuO1byowLlDxNqhHrwStaMN5KWzm2/V/npfgkHAqn8/rw2V6LC9HBwKwBVIhMS2HFu4GoISc + N5O5ZYwRBinZTt7kaDRv7X73JW8BsAorzG54fTGEfMRU2o/JPbj5VXvME3eGo0X/XyLtECN1Ff0ovk/6X7ZaN5PwYXe9dZcyANYlA6w91QlrVJyziVb1TwVvpmSPxL9B+NlCg3JdBDyzOIwHXnxhi2naRxOoBWshMLX4f4yfhlAgMBAAECggEAVePbF1xjRJ/L4Gq9lnL5TZ21BCsourA6le+ZlXf9Fii/xkE7GTh+m0/ylVGUA+XnR1QDAP3c5qlkAVklFojggQHrZi8gHxDpuLb6GNiIFRyy4wH4CJGFNMe4MxMnbvuynEY+4jiMmDnKuhMMF7gIUpLIyanVzrnRhGX9yVqwrb2F3PtVhf/gK0Yib93vsCxJ+Pk4eG88vIt+YEpEZq9mleN8L5M5t/1yBSxVtHIZ/KcXIa1Q/C7AVdbNwNbUi7hQwTOg3RFC1cWwOTJu+0sKIKPs9WsZmo6st+dEde4GNHae07/eL44uYZ+HUE3Z+lcjyNkQHbin5HVG8t/idaSlQQKBgQDYeSr474cJx3SKSPG6Lncz812ibQiirt+5pqsuYlwvWBCjWaAb1H+3YR2/9AfLxBK2hGbbUU1DOvdqi3yOQE742ZhQppDaXOkbwn6ZjnS9GFKdsTHRp/DSafwvuM1zT9BRs1sgTNCGEbzh4PxtJlRn4dht1NZ0fOeymB/IJWgKiQKBgQDFDS5RGwqZ9YxkL6Vb7BV6jnWUq+c39/nTEWDDlfWaWKLss03ox22jG6EewEgHIW/Zvc0nOYRuKvxLcMmK3eU1eK6mZqvo4b1GPqdUqUr6PcRn6acvr8rAAiJBz1ZfHs9/JP9JfA4px0CVlfa6mD3bNRhxWYBkFJ4FBy4wRYtX/QKBgEVv6IbdXnWWkx1gdJmCGh6B7AET9HcqnP0SJ0rDpkpRd1TOhPsoWKdb8Y0HHBESneYJ5mxnUd9E5OQ6RgPjQPG16pPEOiaxMt0CsFVVSsD1Mlr+4bocorT75jbwkoZwjaQHYi2kNicrPWk/H/lrGBwSZ7gjU38eKbwx68/pn8vxAoGAY3yEJe7BK3oNp4dmtUI8lePW+XjRBDDusOHVOOo9Ve/qUhc0/pGxiOgqMJxjwTXggs6RBXzEn9qUBoKrPrFJR/XmN50erjVKmmyHjvbqI+2Le+s7vZfDha2OHivQL7YejNLhEPjRLcarlNph91Nl54anEJNffyfpoCA/8Z8q+wECgYEAvaZY1n3I0Fgx5yoXTHEIQDCT8FTcju2VlkW+mBL9uMwnLtdFzNIwwXrIZgiDJhl+rzecMJieqU4FaoWIUq72+iO8LVeFyauvXRuvhx6k6eh/pPbX6EOOigZoF3yIg/XZbnmmn89NUyQm1fvQQtnWOSosb595CBmny5llYZs57p4=";

            var secretArray = Convert.FromBase64String(consumerSecret);
            var key = opensslkey.DecodePrivateKeyInfo(secretArray);

            var baseUrl = "http://172.25.121.176:8080";

            JiraApplicationCredentials = new ApplicationCredentials
            {
                ConsumerKey = "hardcoded-consumer",
                ConsumerSecret = key.ToXmlString(true)
            };

            JiraOAuth1AProvider = new JIRAOAuth1aProvider(baseUrl);
            OAuth10AStateManager = new OAuth10aStateManager((k, v) => Session[k] = v, k => (string)Session[k]);
        }

        [HttpGet]
        public ActionResult Initate()
        {
            var callback = Request.Url.GetLeftPart(UriPartial.Authority) + "/JiraConnect/Callback";

            var authorizationUri = OAuth1aProcess.GetAuthorizationUri(JiraOAuth1AProvider, JiraApplicationCredentials, callback, OAuth10AStateManager);
            authorizationUri.Wait();

            return new RedirectResult(authorizationUri.Result.AbsoluteUri);
        }

        [HttpGet]
        public ActionResult Callback()
        {
            var processUserResponse = OAuth1aProcess.ProcessUserResponse(JiraOAuth1AProvider, JiraApplicationCredentials,Request.Url, OAuth10AStateManager);
            processUserResponse.Wait();

            Session["access_token"] = processUserResponse.Result.AllParameters["oauth_token"];
            Session["accessTokenSecret"] = processUserResponse.Result.AllParameters["oauth_token_secret"];

            return Redirect("/JiraConnect/IssueInfo");
        }

        public string IssueInfo()
        {
            string result;
            var provider = JiraOAuth1AProvider;
            var jiraCredentials = JiraApplicationCredentials;

            var accessToken = Session["access_token"] as string;
            var accessTokenSecret = Session["accessTokenSecret"] as string;

            const string issueId = "TEST-1";

            string fullUrl = "http://172.25.121.176:8080/rest/api/2/issue/" + issueId;
           
            var http = new Http { Url = new Uri(fullUrl) };
            http.ApplyAccessTokenToHeader(provider, jiraCredentials, accessToken, accessTokenSecret, "GET");

            var request = WebRequest.Create(fullUrl);
            request.Headers["Authorization"] = http.Headers[0].Value;
           
            using (var response = request.GetResponse())
            using (var content = response.GetResponseStream())
            using (var reader = new StreamReader(content))
            {
                result =  reader.ReadToEnd();
            }
         return result;
        }
       
     }
}