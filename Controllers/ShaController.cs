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
        public IActionResult Criptografar([FromBody] DadosSensiveis dadosSensiveis)
        {
            var dadosSensiveisString = JsonSerializer.Serialize(dadosSensiveis);
            _logger.LogInformation($"Dados sensíveis: {dadosSensiveisString}");

            var resultado = new DadosSensiveis
            {
                Nome = CryptoSha.Encrypt(dadosSensiveis.Nome),
                Documento = CryptoSha.Encrypt(dadosSensiveis.Documento),
            };

            var dadosCriptografados = JsonSerializer.Serialize(resultado);
            _logger.LogInformation($"Dados sensíveis criptografados: {dadosCriptografados}");

            return Ok(resultado);
        }
    }
}