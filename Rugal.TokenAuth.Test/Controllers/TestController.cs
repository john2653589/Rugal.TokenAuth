using Microsoft.AspNetCore.Mvc;

namespace Rugal.TokenAuth.Test.Controllers
{
    [ApiController]
    [Route("api/[controller]/[action]")]
    public class TestController : ControllerBase
    {
        public TestController()
        {

        }

        [HttpGet]
        public dynamic TestGet(string Name)
        {
            return new
            {
                Name,
                DateTime = DateTime.Now,
            };
        }

        [HttpPost]
        public dynamic TestPost(string Name)
        {
            return new
            {
                Name,
                DateTime = DateTime.Now,
            };
        }
    }
}
