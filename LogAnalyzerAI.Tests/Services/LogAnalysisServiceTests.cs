using System;
using System.Collections.Generic;
using System.Net;
using System.Net.Http;
using System.Text;
using System.Threading;
using System.Threading.Tasks;
using LogAnalyzerAI.Models;
using LogAnalyzerAI.Services;
using Microsoft.Extensions.Configuration;
using Microsoft.Extensions.Logging.Abstractions;
using Xunit;

namespace LogAnalyzerAI.Tests.Services
{
    public class LogAnalysisServiceTests
    {
        private class FakeHttpMessageHandler : HttpMessageHandler
        {
            private readonly HttpResponseMessage _response;
            public FakeHttpMessageHandler(HttpResponseMessage response) => _response = response;
            protected override Task<HttpResponseMessage> SendAsync(HttpRequestMessage request, CancellationToken cancellationToken)
                => Task.FromResult(_response);
        }

        private class SimpleHttpClientFactory : IHttpClientFactory
        {
            private readonly HttpClient _client;
            public SimpleHttpClientFactory(HttpClient client) => _client = client;
            public HttpClient CreateClient(string name) => _client;
        }

        [Fact]
        public async Task AnalyzeAsync_WithApiResponse_ReturnsParsedResult()
        {
            // Arrange: Mock OpenAI chat completion returning JSON payload inside choices[0].message.content
            var innerJson = "{\"machine\":\"HOST1\",\"ip\":[\"1.2.3.4\"],\"errors\":[\"ERR_LINE\"],\"summary\":\"All good\"}";
            var escaped = innerJson.Replace("\"", "\\\"");
            var apiResponse = "{\"choices\":[{\"message\":{\"content\":\"" + escaped + "\"}}]}";

            var httpResponse = new HttpResponseMessage(HttpStatusCode.OK)
            {
                Content = new StringContent(apiResponse, Encoding.UTF8, "application/json")
            };

            var handler = new FakeHttpMessageHandler(httpResponse);
            var client = new HttpClient(handler);
            var factory = new SimpleHttpClientFactory(client);

            var config = new ConfigurationBuilder().AddInMemoryCollection(new Dictionary<string, string>
            {
                { "OpenAI:ApiKey", "test" }
            }).Build();

            var service = new LogAnalysisService(new NullLogger<LogAnalysisService>(), factory, config);

            // Act
            var result = await service.AnalyzeAsync("irrelevant logs");

            // Assert
            Assert.NotNull(result);
            Assert.Equal("HOST1", result.Machine);
            Assert.Contains("1.2.3.4", result.Ip);
            Assert.Contains("ERR_LINE", result.Errors);
            Assert.Equal("All good", result.Summary);
        }

        [Fact]
        public async Task AnalyzeAsync_WithoutApiKey_FallsBackToLocalAnalysis()
        {
            // Arrange: no API key configured
            var client = new HttpClient();
            var factory = new SimpleHttpClientFactory(client);
            var config = new ConfigurationBuilder().Build();
            var service = new LogAnalysisService(new NullLogger<LogAnalysisService>(), factory, config);

            var logs = "hostname: myserver\nSome normal line\nError: boom occurred\nClient IP 10.0.0.5\n";

            // Act
            var result = await service.AnalyzeAsync(logs);

            // Assert
            Assert.NotNull(result);
            Assert.Equal("myserver", result.Machine);
            Assert.Contains("10.0.0.5", result.Ip);
            // Error pattern matches 'Error' lines
            Assert.True(result.Errors.Count >= 1);
            Assert.False(string.IsNullOrWhiteSpace(result.Summary));
        }
    }
}
