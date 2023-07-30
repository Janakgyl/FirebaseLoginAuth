using System.Diagnostics;
using Microsoft.AspNetCore.Mvc;
using FirebaseLoginAuth.Models;
using Firebase.Auth;
using Newtonsoft.Json;

namespace FirebaseLoginAuth.Controllers;

public class HomeController : Controller
{
    FirebaseAuthProvider auth;

    private readonly ILogger<HomeController> _logger;

    public HomeController(ILogger<HomeController> logger)
    {
        _logger = logger;
        auth = new FirebaseAuthProvider(
                           new FirebaseConfig("AIzaSyAfcLquqVcsckGY1lq6O-pJgZfWPso77_c"));
    }


    public IActionResult Index()
    {
        var token = HttpContext.Session.GetString("_UserToken");

        if (token != null)
        {
            return View();
        }
        else
        {
            return RedirectToAction("SignIn");
        }
    }


    public IActionResult Registration()
    {
        return View();
    }

    [HttpPost]
    public async Task<IActionResult> Registration(LoginModel loginModel)
    {
        try
        {
            //create the user
            await auth.CreateUserWithEmailAndPasswordAsync(loginModel.Email, loginModel.Password);
            //log in the new user
            var fbAuthLink = await auth
                            .SignInWithEmailAndPasswordAsync(loginModel.Email, loginModel.Password);
            string token = fbAuthLink.FirebaseToken;
            //saving the token in a session variable
            if (token != null)
            {
                HttpContext.Session.SetString("_UserToken", token);

                return RedirectToAction("Index");
            }
        }
        catch (FirebaseAuthException ex)
        {
            var firebaseEx = JsonConvert.DeserializeObject<FirebaseError>(ex.ResponseData);
            ModelState.AddModelError(String.Empty, firebaseEx.error.message);
            return View(loginModel);
        }

        return View();

    }

    public IActionResult SignIn()
    {
        return View();
    }

    [HttpPost]
    public async Task<IActionResult> SignIn(LoginModel loginModel)
    {
        try
        {
            //log in an existing user
            var fbAuthLink = await auth
                            .SignInWithEmailAndPasswordAsync(loginModel.Email, loginModel.Password);
            string token = fbAuthLink.FirebaseToken;
            //save the token to a session variable
            if (token != null)
            {
                HttpContext.Session.SetString("_UserToken", token);

                return RedirectToAction("Index");
            }

        }
        catch (FirebaseAuthException ex)
        {
            var firebaseEx = JsonConvert.DeserializeObject<FirebaseError>(ex.ResponseData);
            ModelState.AddModelError(String.Empty, firebaseEx.error.message);
            return View(loginModel);
        }

        return View();
    }

    public IActionResult LogOut()
    {
        HttpContext.Session.Remove("_UserToken");
        return RedirectToAction("SignIn");
    }

    [ResponseCache(Duration = 0, Location = ResponseCacheLocation.None, NoStore = true)]
    public IActionResult Error()
    {
        return View(new ErrorViewModel { RequestId = Activity.Current?.Id ?? HttpContext.TraceIdentifier });
    }
}

