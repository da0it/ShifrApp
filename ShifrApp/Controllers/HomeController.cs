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

		// ������� ��������

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
                model.EncryptedString = "����������, ������� ������ ��� ����������.";
            }
            return View("Index", model);
        }
        [ResponseCache(Duration = 0, Location = ResponseCacheLocation.None, NoStore = true)]

		// ����� ��� ��������� ��������� ������
		public IActionResult Error()
		{
			return View(new ErrorViewModel { RequestId = Activity.Current?.Id ?? HttpContext.TraceIdentifier });
		}



		private string EncryptSha256(string rawData)
		{
			using (SHA256 sha256Hash = SHA256.Create())
			{
				//���������� ����
				byte[] bytes = sha256Hash.ComputeHash(Encoding.UTF8.GetBytes(rawData));

				// �������������� ������ � ������ (hex ������)
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
