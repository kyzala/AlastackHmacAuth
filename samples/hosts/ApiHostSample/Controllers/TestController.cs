using Microsoft.AspNetCore.Authorization;
using Microsoft.AspNetCore.Mvc;

namespace ApiHostSample.Controllers;

[Authorize]
[Route("api/[controller]")]
[ApiController]
public class TestController : ControllerBase
{        
    [HttpGet("{id}")]
    public ActionResult<TestItem> GetItem(long id)
    {
        return new TestItem { Id = id, Name = "Alastack" };
    }

    [HttpPut("{id}")]
    public IActionResult UpdateItem(long id, TestItem testItem)
    {
        if (id != testItem.Id)
        {
            return BadRequest();
        }
        return NoContent();
    }
    
    [HttpPost]
    public ActionResult<TestItem> CreateItem(TestItem testItem)
    {
        return CreatedAtAction(nameof(GetItem), new { id = testItem.Id }, testItem);
    }
    
    [HttpDelete("{id}")]
    public IActionResult DeleteItem(long id)
    {
        return NoContent();
    }

    [HttpGet("claims")]
    public IActionResult GetClaims()
    {
        return Ok(User.Claims.Select(c => new { Name = c.Type, Value = c.Value }));
    }

    public class TestItem
    {
        public long Id { get; set; }
        public string Name { get; set; } = default!;
    }
}