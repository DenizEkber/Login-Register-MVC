using Microsoft.AspNetCore.Mvc;
using Microsoft.Extensions.Logging;
using System;
using System.Data.SqlClient;
using LoginRegister.Models;
using Microsoft.Extensions.Configuration;

namespace LoginRegister.Controllers
{
    public class AccountController : Controller
    {
        private readonly string _connectionString;
        private readonly ILogger<AccountController> _logger;

        public AccountController(IConfiguration configuration, ILogger<AccountController> logger)
        {
            _connectionString = configuration.GetConnectionString("DefaultConnection");
            _logger = logger;
        }

        
        public IActionResult Register()
        {
            return View();
        }

        
        [HttpPost]
        [ValidateAntiForgeryToken]
        public IActionResult Register(User user)
        {
            _logger.LogInformation("Register action in AccountController called.");

            try
            {
                string salt;
                user.Hash = PasswordHelper.HashPassword(user.Password, out salt);
                user.Salt = salt;

                using (SqlConnection conn = new SqlConnection(_connectionString))
                {
                    string query = "INSERT INTO Users (UserName, Email, Hash, Salt) VALUES (@Username, @Email, @Hash, @Salt)";
                    SqlCommand cmd = new SqlCommand(query, conn);
                    cmd.Parameters.AddWithValue("@Username", user.Username);
                    cmd.Parameters.AddWithValue("@Email", user.Email);
                    cmd.Parameters.AddWithValue("@Hash", user.Hash);
                    cmd.Parameters.AddWithValue("@Salt", user.Salt);

                    conn.Open();
                    cmd.ExecuteNonQuery();
                    conn.Close();

                    _logger.LogInformation("User successfully inserted into the database.");
                }

                return RedirectToAction("Login");
            }
            catch (Exception ex)
            {
                _logger.LogError(ex, "An error occurred while inserting the user into the database.");
                ModelState.AddModelError(string.Empty, "An error occurred while processing your request.");
            }

            _logger.LogWarning("Model state is not valid.");
            return View(user);
        }

        
        public IActionResult Login()
        {
            return View();
        }

       
        [HttpPost]
        [ValidateAntiForgeryToken]
        public IActionResult Login(string email, string password)
        {
            try
            {
                User user = null;

                using (SqlConnection conn = new SqlConnection(_connectionString))
                {
                    string query = "SELECT Id, UserName, Email, Hash, Salt FROM Users WHERE Email = @Email";
                    SqlCommand cmd = new SqlCommand(query, conn);
                    cmd.Parameters.AddWithValue("@Email", email);

                    conn.Open();
                    SqlDataReader reader = cmd.ExecuteReader();
                    if (reader.Read())
                    {
                        string storedHash = reader["Hash"].ToString();
                        string storedSalt = reader["Salt"].ToString();

                        if (PasswordHelper.VerifyPassword(password, storedHash, storedSalt))
                        {
                            user = new User
                            {
                                Id = (int)reader["Id"],
                                Username = reader["UserName"].ToString(),
                                Email = reader["Email"].ToString()
                            };
                        }
                    }
                    conn.Close();
                }

                if (user != null)
                {
                    
                    return RedirectToAction("Index", "Home");
                }
                else
                {
                    
                    ModelState.AddModelError(string.Empty, "Invalid login attempt.");
                }
            }
            catch (Exception ex)
            {
                _logger.LogError(ex, "An error occurred while logging in.");
                ModelState.AddModelError(string.Empty, "An error occurred while processing your request.");
            }

            return View();
        }
    }
}
