using Microsoft.AspNetCore.Mvc;
using kriptografi.Models;
using Microsoft.Extensions.Logging;

namespace kriptografi.Controllers
{
    public class CryptoController : Controller
    {
        private readonly ILogger<CryptoController> _logger;

        public CryptoController(ILogger<CryptoController> logger)
        {
            _logger = logger;
        }

        public IActionResult Index()
        {
            return View(new CryptoModel());
        }

        [HttpPost]
        [RequestSizeLimit(100 * 1024 * 1024)]
        public async Task<IActionResult> Process([FromForm] CryptoModel model)
        {
            try
            {
                _logger.LogInformation($"Selected Operation: {model.SelectedOperation}");

                if (model.GenerateNewKeys)
                {
                    var (publicKey, privateKey) = CryptoHelper.GenerateRSAKeys();
                    model.PublicKey = publicKey;
                    model.PrivateKey = privateKey;
                    model.OutputText = $"Yeni RSA anahtar çifti oluşturuldu.\n\n" +
                                     $"Public Key:\n{publicKey}\n\n" +
                                     $"Private Key:\n{privateKey}";
                    return View("Index", model);
                }

                if (model.GenerateAesKey)
                {
                    var (key, iv) = CryptoHelper.GenerateAesKey();
                    model.AesKey = key;
                    model.AesIV = iv;
                    model.OutputText = $"Yeni AES anahtarı ve IV oluşturuldu.\n\n" +
                                     $"AES Key:\n{key}\n\n" +
                                     $"AES IV:\n{iv}";
                    return View("Index", model);
                }

                if (string.IsNullOrEmpty(model.SelectedOperation))
                {
                    ModelState.AddModelError("", "Lütfen bir işlem seçin.");
                    return View("Index", model);
                }

                switch (model.SelectedOperation)
                {
                    case "encrypt":
                        if (string.IsNullOrEmpty(model.InputText) || string.IsNullOrEmpty(model.PublicKey))
                        {
                            ModelState.AddModelError("", "Lütfen metin ve public key girin.");
                            break;
                        }
                        model.OutputText = CryptoHelper.EncryptRSA(model.InputText, model.PublicKey);
                        break;

                    case "decrypt":
                        if (string.IsNullOrEmpty(model.InputText) || string.IsNullOrEmpty(model.PrivateKey))
                        {
                            ModelState.AddModelError("", "Lütfen şifreli metin ve private key girin.");
                            break;
                        }
                        model.OutputText = CryptoHelper.DecryptRSA(model.InputText, model.PrivateKey);
                        break;

                    case "aes-encrypt":
                        if (string.IsNullOrEmpty(model.InputText) || string.IsNullOrEmpty(model.AesKey) || string.IsNullOrEmpty(model.AesIV))
                        {
                            ModelState.AddModelError("", "Lütfen metin, AES Key ve IV girin.");
                            break;
                        }
                        model.OutputText = CryptoHelper.EncryptAES(model.InputText, model.AesKey, model.AesIV);
                        break;

                    case "aes-decrypt":
                        if (string.IsNullOrEmpty(model.InputText) || string.IsNullOrEmpty(model.AesKey) || string.IsNullOrEmpty(model.AesIV))
                        {
                            ModelState.AddModelError("", "Lütfen şifreli metin, AES Key ve IV girin.");
                            break;
                        }
                        model.OutputText = CryptoHelper.DecryptAES(model.InputText, model.AesKey, model.AesIV);
                        break;

                    case "sha256text":
                        if (string.IsNullOrEmpty(model.InputText))
                        {
                            ModelState.AddModelError("", "Lütfen metin girin.");
                            break;
                        }
                        model.OutputText = CryptoHelper.CalculateSHA256(model.InputText);
                        break;

                    case "sha256file":
                        if (model.InputFile == null || model.InputFile.Length == 0)
                        {
                            ModelState.AddModelError("", "Lütfen bir dosya seçin.");
                            break;
                        }

                        if (model.InputFile.Length > 100 * 1024 * 1024)
                        {
                            ModelState.AddModelError("", "Dosya boyutu 100MB'dan büyük olamaz.");
                            break;
                        }

                        try
                        {
                            model.OutputText = await CryptoHelper.CalculateFileSHA256Async(model.InputFile);
                            _logger.LogInformation($"SHA256 hash calculated for file: {model.InputFile.FileName}");
                        }
                        catch (Exception ex)
                        {
                            _logger.LogError($"Error processing file: {ex.Message}");
                            ModelState.AddModelError("", $"Dosya işlenirken hata oluştu: {ex.Message}");
                        }
                        break;

                    default:
                        ModelState.AddModelError("", "Geçersiz işlem.");
                        break;
                }
            }
            catch (Exception ex)
            {
                _logger.LogError($"Process error: {ex.Message}");
                ModelState.AddModelError("", $"İşlem sırasında bir hata oluştu: {ex.Message}");
            }

            return View("Index", model);
        }
    }
} 