using crypto.Crypto.Tripledes;
using crypto.Models;
using Microsoft.AspNetCore.Mvc;
using System.Text.Json;

namespace crypto.Controllers
{
    [ApiController]
    [Route("[controller]")]
    public class TripledesController : ControllerBase
    {
        private readonly ILogger<TripledesController> _logger;

        public TripledesController(ILogger<TripledesController> logger)
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
                Nome = CryptoTripledes.Encrypt(dadosSensiveis.Nome),
                Documento = CryptoTripledes.Encrypt(dadosSensiveis.Documento),
            };

            var dadosCriptografados = JsonSerializer.Serialize(resultado);
            _logger.LogInformation($"Dados sensíveis criptografados: {dadosCriptografados}");

            return Ok(resultado);
        }

        [HttpPost("descriptografar")]
        public IActionResult Descriptografar([FromBody] DadosSensiveis dadosSensiveis)
        {
            var dadosSensiveisString = JsonSerializer.Serialize(dadosSensiveis);
            _logger.LogInformation($"Dados sensíveis criptografados: {dadosSensiveisString}");

            var resultado = new DadosSensiveis
            {
                Nome = CryptoTripledes.Decrypt(dadosSensiveis.Nome),
                Documento = CryptoTripledes.Decrypt(dadosSensiveis.Documento),
            };

            var dadosCriptografados = JsonSerializer.Serialize(resultado);
            _logger.LogInformation($"Dados sensíveis descriptografados: {dadosCriptografados}");

            return Ok(resultado);
        }
    }
}