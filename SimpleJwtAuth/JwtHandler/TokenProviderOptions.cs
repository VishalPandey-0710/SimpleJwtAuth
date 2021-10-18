using Microsoft.IdentityModel.Tokens;
using System;
using System.Collections.Generic;
using System.Linq;
using System.Security.Claims;
using System.Threading.Tasks;

namespace SimpleJwtAuth.JwtHandler
{
    public class TokenProviderOptions
    {
        /// <summary>
        /// The relative request path to listen on.
        /// </summary>
        /// <remarks>The default path is <c>/token</c>.</remarks>
        public string Path { get; set; } = "/token";

        /// <summary>
        ///  The Issuer (iss) claim for generated tokens.
        /// </summary>
        public string Issuer { get; set; }

        /// <summary>
        /// The Audience (aud) claim for the generated tokens.
        /// </summary>
        public string Audience { get; set; }
        //public string NonceGenerator { get; set; }
        

        /// <summary>
        /// The expiration time for the generated tokens.
        /// </summary>
        /// <remarks>The default is five minutes (300 seconds).</remarks>
        public TimeSpan Expiration { get; set; } = TimeSpan.FromMinutes(5);

        /// <summary>
        /// The signing key to use when generating tokens.
        /// </summary>
        public SigningCredentials SigningCredentials { get; set; }

        /// <summary>
        /// Resolves a user identity given a username and password.
        /// </summary>
        public Func<string, string, Task<ClaimsIdentity>> IdentityResolver { get; set; }
        private static readonly Random random = new Random();
        private static readonly object randLock = new object();
        public string NonceGenerator()
        {
            lock (randLock)
            {
                // Just a simple implementation of a random number between 123400 and 9999999
                return random.Next(123400, 9999999).ToString();
            }
        }

    }
}
