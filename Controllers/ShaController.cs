using crypto.Crypto.Sha;
using crypto.Models;
using Microsoft.AspNetCore.Mvc;
using System.Text.Json;

namespace crypto.Controllers
{
    [ApiController]
    [Route("[controller]")]
    public class ShaController : ControllerBase
    {
        private readonly ILogger<ShaController> _logger;

        public ShaController(ILogger<ShaController> logger)
        {
            _logger = logger;
        }

        [HttpPost("criptografar")]
        public IActionResult Criptografar([FromBody] Senha senha)
        {
            var senhaString = JsonSerializer.Serialize(senha);
            _logger.LogInformation($"Senha aberta: {senhaString}");

            var resultado = new Senha
            {
                Valor = CryptoSha.Encrypt(senha.Valor)
            };

            var senhaCriptografada = JsonSerializer.Serialize(resultado);
            _logger.LogInformation($"Senha criptografada: {senhaCriptografada}");

            return Ok(resultado);
        }
    }
}