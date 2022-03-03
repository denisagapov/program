using System;
using System.IO;
using System.Security.Cryptography;
class AesMethod
{
    public static void Main()
    {
        Console.WriteLine("Enter text that needs to be encrypted..");
        string data = Console.ReadLine();
        EncryptAesManaged(data);
        Console.ReadLine();
    }
    static void EncryptAesManaged(string raw)
    {
        try
        {
            // Cоздаем AES для генерации ключа и инициализации вектора для сцепки блоков (IV)  
            // Ключ использует для шифровки и расшифровки    
            using (AesManaged aes = new AesManaged())
            {
                // Шифруем строку   
                byte[] encrypted = Encrypt(raw, aes.Key, aes.IV);
                // Печатаем зашифрованную строку  
                Console.WriteLine($"Encrypted message: {System.Text.Encoding.UTF8.GetString(encrypted)}");
                // Расшифровываем строку   
                string decrypted = Decrypt(encrypted, aes.Key, aes.IV);
                // Печатаем расшифрованную строку (она должна быть такой же как изначальный текст).    
                Console.WriteLine($"Decrypted message: {decrypted}");
            }
        }
        catch (Exception exp)
        {
            Console.WriteLine(exp.Message);
        }
        Console.ReadKey();
    }
    static byte[] Encrypt(string plainText, byte[] Key, byte[] IV)
    {
        byte[] encrypted;
        // создаем новый AESManaged   
        using (AesManaged aes = new AesManaged())
        {
            // Создаем шифратор    
            ICryptoTransform encryptor = aes.CreateEncryptor(Key, IV);
            // Создаем MemoryStream (класс потоков для хранения информации)   
            using (MemoryStream ms = new MemoryStream())
            {
                // Создаем класс CryptoStream для работы с шифром, используя для обеих операций. 
                using (CryptoStream cs = new CryptoStream(ms, encryptor, CryptoStreamMode.Write))
                {
                    // Запись получаемого текста    
                    using (StreamWriter sw = new StreamWriter(cs))
                        sw.Write(plainText);
                    encrypted = ms.ToArray();
                }
            }
        }
        // Возврат зашифр. сообщения   
        return encrypted;
    }
    static string Decrypt(byte[] cipherText, byte[] Key, byte[] IV)
    {
        string plaintext = null;
        // Создаeм AesManaged    
        using (AesManaged aes = new AesManaged())
        {
            // Создаем расшифровщик   
            ICryptoTransform decryptor = aes.CreateDecryptor(Key, IV);
            // Создаем MemoryStream    
            using (MemoryStream ms = new MemoryStream(cipherText))
            {
                // Cоздаем CryptoStream   
                using (CryptoStream cs = new CryptoStream(ms, decryptor, CryptoStreamMode.Read))
                {
                    // Считываем информацию для расшифровки  
                    using (StreamReader reader = new StreamReader(cs))
                        plaintext = reader.ReadToEnd();
                }
            }
        }
        return plaintext; // Возврат расшифрованного сообщения.
    }
}
