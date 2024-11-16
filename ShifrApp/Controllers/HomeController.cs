using Microsoft.AspNetCore.Mvc;
using ShifrApp.Models;
using System.Diagnostics;
using ShifrApp.Models;
using System.Security.Cryptography;
using System.Text;
using System.Runtime.Intrinsics.Arm;

namespace ShifrApp.Controllers
{
	public class HomeController : Controller
	{
		private readonly ILogger<HomeController> _logger;

		public HomeController(ILogger<HomeController> logger)
		{
			_logger = logger;
		}

		// Главная страница

		[HttpGet]
		public IActionResult Index()
		{
			return View(new EncryptionModel());
		}

		[HttpPost]
        public IActionResult Index(EncryptionModel model)
        {
            if (!string.IsNullOrEmpty(model.Input))
            {
                model.EncryptedString = EncryptSha256(model.Input);
            }
            else
            {
                model.EncryptedString = "Пожалуйста, введите строку для шифрования.";
            }
            return View("Index", model);
        }
        [ResponseCache(Duration = 0, Location = ResponseCacheLocation.None, NoStore = true)]

		// Метод для обработки введенной строки
		public IActionResult Error()
		{
			return View(new ErrorViewModel { RequestId = Activity.Current?.Id ?? HttpContext.TraceIdentifier });
		}



		private string EncryptSha256(string rawData)
		{
			using (SHA256 sha256Hash = SHA256.Create())
			{
				//вычисление хэша
				byte[] bytes = sha256Hash.ComputeHash(Encoding.UTF8.GetBytes(rawData));

				// Преобразование байтов в строку (hex формат)
				StringBuilder builder = new StringBuilder();
				for (int i = 0; i < bytes.Length; i++)
				{
					builder.Append(bytes[i].ToString("x2"));
				}
				return builder.ToString();
			}
		}
	}
}
