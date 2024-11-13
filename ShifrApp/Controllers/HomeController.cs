using Microsoft.AspNetCore.Mvc;
using ShifrApp.Models;
using System.Diagnostics;
using ShifrApp.Models;
using System.Security.Cryptography;
using System.Text;
using System.Runtime.Intrinsics.Arm;
using ShifrApp.cipher;


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
                model.EncryptedString = EncryptGrassHopper2(model.Input);
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

        private static string EncryptGrassHopper2(string text) //Заглушка - на вход всегда подается тестовое значение для проверки корректности работы шифра
		{
            byte[] result = System.Convert.FromHexString(text);
            byte[] padded_text = PaddArray(result);
            Array.Reverse(padded_text);
            string out_data = cipher.Kuznechik.KuznechikEncrypt(padded_text);
			return out_data;
        }

        //Добавление нулей в массив байтов, если длина сообщения меньше BLOCK_SIZE
        static byte[] PaddArray(byte[] bytes)
        {
            if (bytes.Length < 16)
            {
                byte[] paddedBytes = new byte[16];
                Array.Copy(bytes, paddedBytes, bytes.Length);
                return paddedBytes;
            }
            return bytes;
        }
    }
}
