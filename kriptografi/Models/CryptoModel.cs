using System.ComponentModel.DataAnnotations;
using Microsoft.AspNetCore.Http;

namespace kriptografi.Models
{
    public class CryptoModel
    {
        public string? InputText { get; set; }
        
        public string? OutputText { get; set; }
        
        [Display(Name = "Dosya")]
        public IFormFile? InputFile { get; set; }
        
        public string? SelectedOperation { get; set; }
        
        public string? PublicKey { get; set; }
        
        public string? PrivateKey { get; set; }
        
        public bool GenerateNewKeys { get; set; }

        // AES için yeni özellikler
        public string? AesKey { get; set; }
        
        public string? AesIV { get; set; }
        
        public bool GenerateAesKey { get; set; }
    }
} 