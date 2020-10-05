using System;

namespace Auth_AD_domains
{
	public class AuthorizedAdDomains
	{
		public string domain
		{
			get;
			private set;
		}

		public string upn
		{
			get;
			private set;
		}

		public AuthorizedAdDomains(string domain, string upn)
		{
			this.domain = domain.ToLower();
			this.upn = upn.ToLower();
		}
	}
}
