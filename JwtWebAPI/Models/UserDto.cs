﻿namespace JwtWebAPI.Models
{
    public class UserDto
    {
        public required string UserName { get; set; } = string.Empty;
        public required string Password { get; set; } = string.Empty;
    }
}