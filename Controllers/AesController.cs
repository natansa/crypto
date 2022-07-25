using crypto.Crypto.Aes;
using crypto.Crypto.Tripledes;
using crypto.Models;
using Microsoft.AspNetCore.Mvc;
using System.Text.Json;

namespace crypto.Controllers
{
    [ApiController]
    [Route("[controller]")]
    public class AesController : ControllerBase
    {
        private readonly ILogger<AesController> _logger;
        private readonly CryptoAes _cryptoAes;

        public AesController(ILogger<AesController> logger)
        {
            _logger = logger;
            _cryptoAes = new CryptoAes();
        }

        [HttpPost("criptografar")]
        public IActionResult Criptografar([FromBody] DadosSensiveis dadosSensiveis)
        {
            var dadosSensiveisString = JsonSerializer.Serialize(dadosSensiveis);
            _logger.LogInformation($"Dados sensíveis: {dadosSensiveisString}");

            var resultado = new DadosSensiveis
            {
                Nome = _cryptoAes.Encrypt(dadosSensiveis.Nome),
                Documento = _cryptoAes.Encrypt(dadosSensiveis.Documento),
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
                Nome = _cryptoAes.Decrypt(dadosSensiveis.Nome),
                Documento = _cryptoAes.Decrypt(dadosSensiveis.Documento),
            };

            var dadosCriptografados = JsonSerializer.Serialize(resultado);
            _logger.LogInformation($"Dados sensíveis descriptografados: {dadosCriptografados}");

            return Ok(resultado);
        }
    }
}