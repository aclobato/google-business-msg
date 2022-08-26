using Flurl;
using Flurl.Http;
using Google.Apis.Auth.OAuth2;
using System.Security.Cryptography;
using System.Text;
using System.Text.Json;
using System.Text.Json.Serialization;

var builder = WebApplication.CreateBuilder(args);

// Add services to the container.
// Learn more about configuring Swagger/OpenAPI at https://aka.ms/aspnetcore/swashbuckle
builder.Services.AddEndpointsApiExplorer();
builder.Services.AddSwaggerGen();

var app = builder.Build();

// Configure the HTTP request pipeline.
if (app.Environment.IsDevelopment())
{
    app.UseSwagger();
    app.UseSwaggerUI();
}

app.Urls.Add("http://localhost:4000");

var credentialPath = builder.Configuration["CredentialPath"];
var clientToken = builder.Configuration["ClientToken"];

app.MapPost("/webhook", async (HttpRequest request) =>
{
    var googleSignature = request.Headers["X-Goog-Signature"].ToString();
    string jsonConversation = await GetJsonConversation(request);
    var conversation = JsonSerializer.Deserialize<Conversation>(jsonConversation);

    if (IsVerificationMessage(conversation))
    {
        return VerifyWebhook(conversation, clientToken);
    }

    if (!IsValidMessage(googleSignature, clientToken, jsonConversation))
    {
        return Results.BadRequest("Mensagem inválida");
    }

    dynamic result = "";
    if (IsTextMessage(conversation))
    {
        result = await SendEcho(credentialPath, conversation);
    }

    return Results.Ok(result);
});

app.Run();

static string GetAccessTokenFromJSONKey(string jsonKeyFilePath, params string[] scopes)
{
    return GetAccessTokenFromJSONKeyAsync(jsonKeyFilePath, scopes).Result;
}

static async Task<string> GetAccessTokenFromJSONKeyAsync(string jsonKeyFilePath, params string[] scopes)
{
    using var stream = new FileStream(jsonKeyFilePath, FileMode.Open, FileAccess.Read);
    return await GoogleCredential
        .FromStream(stream)
        .CreateScoped(scopes) 
        .UnderlyingCredential 
        .GetAccessTokenForRequestAsync(); 
}

static bool IsValidMessage(string googleSignature, string clientToken, string jsonMessage)
{
    var hmac = new HMACSHA512(Encoding.ASCII.GetBytes(clientToken));
    var generatedSignature = Convert.ToBase64String(hmac.ComputeHash(Encoding.ASCII.GetBytes(jsonMessage)));
    return generatedSignature.Equals(googleSignature);
}

static async Task<string> GetJsonConversation(HttpRequest request)
{
    string jsonConversation = "";
    using (StreamReader stream = new(request.Body))
    {
        jsonConversation = await stream.ReadToEndAsync();
    }

    return jsonConversation;
}

static async Task<dynamic> SendEcho(string credentialPath, Conversation? conversation)
{
    var token = GetAccessTokenFromJSONKey(
        credentialPath,
        "https://www.googleapis.com/auth/businessmessages");

    var url = $"https://businessmessages.googleapis.com/v1/conversations";
    var result = await url
        .AppendPathSegment(conversation?.ConversationId)
        .AppendPathSegment("messages")
        .WithOAuthBearerToken(token)
        .PostJsonAsync(new
        {
            messageId = Guid.NewGuid(),
            text = "Echo: " + conversation?.Message.Text,
            representative = new
            {
                displayName = "Nome Bot",
                representativeType = "BOT"
            }
        })
        .ReceiveJson();
    return result;
}

static bool IsVerificationMessage(Conversation? conversation)
{
    return conversation != null && conversation?.Secret != null;
}

static bool IsTextMessage(Conversation? conversation)
{
    return conversation != null && conversation.Message != null;
}

static dynamic VerifyWebhook(Conversation? conversation, string clientToken)
{
    if (clientToken.Equals(conversation?.ClientToken))
        return Results.Ok(conversation.Secret);
    else
        return Results.Unauthorized();
}

class Conversation
{
    [JsonPropertyName("clientToken")]
    public string? ClientToken { get; set; }

    [JsonPropertyName("secret")]
    public string? Secret { get; set; }

    [JsonPropertyName("conversationId")]
    public string? ConversationId { get; set; }

    [JsonPropertyName("message")]
    public Message? Message { get; set; }
}

class Message
{
    [JsonPropertyName("text")]
    public string? Text { get; set; }
}
