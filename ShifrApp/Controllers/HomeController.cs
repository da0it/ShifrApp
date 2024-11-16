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
                model.EncryptedString = EncryptGrassHopper2(model.Input);
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

        private static string EncryptGrassHopper2(string text) //�������� - �� ���� ������ �������� �������� �������� ��� �������� ������������ ������ �����
		{
            byte[] result = System.Convert.FromHexString(text);
            byte[] padded_text = PaddArray(result);
            Array.Reverse(padded_text);
            string out_data = cipher.Kuznechik.KuznechikEncrypt(padded_text);
			return out_data;
        }

        //���������� ����� � ������ ������, ���� ����� ��������� ������ BLOCK_SIZE
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
