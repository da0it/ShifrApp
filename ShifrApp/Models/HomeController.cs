using Microsoft.AspNetCore.Mvc;

namespace ShifrApp.Models
{
	public class EncryptionModel
	{
		public string Input { get; set; }
		public string EncryptedString { get; set; }
	}
}
