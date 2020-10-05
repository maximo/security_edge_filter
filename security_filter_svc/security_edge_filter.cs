using Auth_AD_domains;
using Lync.Utils;
using Microsoft.Rtc.Sip;
using System;
using System.Collections;
using System.Collections.Generic;
using System.Data.EntityClient;
using System.Data.SqlClient;
using System.Diagnostics;
using System.Linq;
using System.Security.Cryptography.X509Certificates;
using System.Text;

namespace security_edge_filter
{
	internal class SecurityEdgeFilter
	{
		private class LyncUser
		{
			private string username;
			private string client_type;

			public LyncUser(string user, string clientType)
			{
				this.username = user;
				this.client_type = clientType;
			}

			public string GetUsername() { return this.username; }

			public string GetClientType() { return this.client_type; }
		}

        private bool cSqlDependency;

		private const int cAuthorized = 200;
		private const int cUnauthorized = 401;
		private char[] TERMINATOR = new char[]
		{
			'\r', '\n'
		};

		private uint cMaxCount;
		private uint cMaxPeriod;
		private bool cBlockNTLM;
		private bool cWhiteList;
		private bool cDeviceAuthorization;

		private List<string> cInternalSubnets;
		private List<AuthorizedAdDomains> cAdDomains;
		private EntityConnectionStringBuilder cEntity;
		private Hashtable cUsers;

		private AppEventLog cEventLog;
		private string cLogLevel;

		public SecurityEdgeFilter(EntityConnectionStringBuilder entity, AppEventLog log, string level)
		{
            // turn off SQL Dependency.
            cSqlDependency = true;

			cEventLog = log;
			cLogLevel = level;
			cEntity = entity;

			cUsers = new Hashtable();

			cInternalSubnets = new List<string>();
			cAdDomains = new List<AuthorizedAdDomains>();
			UpdateAuthorizedDomains();
			UpdateConfigSettings();
		}
        private void Domains_SqlDependencyOnChange(object sender, SqlNotificationEventArgs e)
        {

            UpdateAuthorizedDomains();
        }

		private bool UpdateAuthorizedDomains()
		{
			bool result = false;

            if(cSqlDependency)
            {
                string _sqlcmd = @"SELECT [NetBIOS], [UPN] from [dbo].[AuthorizedDomains]";

                try
                {
                    using (SqlConnection _connection = new SqlConnection(cEntity.ProviderConnectionString))
                    {
                        using (SqlCommand _command = new SqlCommand(_sqlcmd, _connection))
                        {
                            SqlDependency _dependency = new SqlDependency(_command);
                            _dependency.OnChange += new OnChangeEventHandler(Domains_SqlDependencyOnChange);

                            // open connection, execute a non-query to subscribe for updates, and close connection.
                            _connection.Open();
                            _command.ExecuteNonQuery();
                            _connection.Close();
                        }
                    }
                }
                catch (Exception ex)
                {
                    System.Diagnostics.Trace.WriteLine("SQL Server notification configuration failed [AuthorizedDomains]\n" + ex.InnerException.Message.ToString());
                    return result;
                }
            }

			try
			{
				using (AccountEntities context = new AccountEntities(this.cEntity.ToString()))
				{
					List<AuthorizedDomain> _domains = context.AuthorizedDomains.ToList<AuthorizedDomain>();
					cAdDomains.Clear();

					foreach (AuthorizedDomain domain in _domains)
					{
						cAdDomains.Add(new AuthorizedAdDomains(domain.NetBIOS, domain.UPN));
					}
				}

                // output configuration.
                System.Diagnostics.Trace.WriteLine("\ninternal Active Directory domains: ");

                if (cEventLog != null)
                {
                    cEventLog.LogInfo("internal Active Directory domains: ");
                }

                foreach (AuthorizedAdDomains _authAD in cAdDomains)
                {
                    System.Diagnostics.Trace.WriteLine("\tdomain: " +
                            (_authAD.domain == null ? "\t\t" : _authAD.domain) +
                            "\t\t\tupn: " + (_authAD.upn == null ? "" : _authAD.upn));
                    if (cEventLog != null)
                        cEventLog.LogInfo("\tdomain: " +
                                (_authAD.domain == null ? "\t\t" : _authAD.domain) +
                                "\t\t\tupn: " + (_authAD.upn == null ? "" : _authAD.upn));
                }

				result = true;
			}
			catch (Exception ex)
			{
				Trace.WriteLine("Please correct the following issue and restart this service.\n\nDatabase: failed to connect to SQL instance or more than one entry exists in the AuthorizedDomains table\n" + ex.InnerException.Message.ToString());
			}

			return result;
		}


        private void Settings_SqlDependencyOnChange(object sender, SqlNotificationEventArgs e)
        {

            UpdateConfigSettings();
        }

		private bool UpdateConfigSettings()
		{
			bool result = false;

            if (cSqlDependency)
            {
                string _sqlcmd = @"SELECT [Count], [Period], [WhiteList], [BlockNTLM], [EnforceDeviceAuthorization], [InternalNetworkSubnets] from [dbo].[SecurityFilterSettings]";

                try
                {
                    using (SqlConnection _connection = new SqlConnection(cEntity.ProviderConnectionString))
                    {
                        using (SqlCommand _command = new SqlCommand(_sqlcmd, _connection))
                        {
                            SqlDependency _dependency = new SqlDependency(_command);
                            _dependency.OnChange += new OnChangeEventHandler(Settings_SqlDependencyOnChange);

                            // open connection, execute a non-query to subscribe for updates, and close connection.
                            _connection.Open();
                            _command.ExecuteNonQuery();
                            _connection.Close();
                        }
                    }
                }
                catch (Exception ex)
                {
                    System.Diagnostics.Trace.WriteLine("SQL Server notification configuration failed [SecurityFilterSettings]\n" + ex.InnerException.Message.ToString());
                    return result;
                }
            }

			try
			{
				using (AccountEntities context = new AccountEntities(this.cEntity.ToString()))
				{
					SecurityFilterSetting _config = context.SecurityFilterSettings.SingleOrDefault<SecurityFilterSetting>();
                    // update configuration settings entry.
                    try
                    {
                        cMaxCount = (uint)_config.Count;
                        System.Diagnostics.Trace.WriteLine("\nlockout count: " + cMaxCount.ToString());
                    }
                    catch
                    {
                        System.Diagnostics.Trace.WriteLine("Lockout count policy not configured in Security Filter Manager.");
                    }

                    try
                    {
                        cMaxPeriod = (uint)_config.Period;
                        System.Diagnostics.Trace.WriteLine("lockout duration: " + cMaxPeriod.ToString());
                    }
                    catch
                    {
                        System.Diagnostics.Trace.WriteLine("Lockout duration policy not configured in Security Filter Manager.");
                    }

                    try
                    {
                        cWhiteList = (bool)_config.WhiteList;
                        System.Diagnostics.Trace.WriteLine("block unauthorized domains: " + cWhiteList.ToString());
                    }
                    catch
                    {
                        System.Diagnostics.Trace.WriteLine("Block unauthorized domains policy not configured in Security Filter Manager");
                    }

                    try
                    {
                        cBlockNTLM = (bool)_config.BlockNTLM;
                        System.Diagnostics.Trace.WriteLine("block NTLM authentication: " + cBlockNTLM.ToString());
                    }
                    catch
                    {
                        System.Diagnostics.Trace.WriteLine("Block NTLM authentication policy not configured in Security Filter Manager.");
                    }

					this.cInternalSubnets.Clear();
                    try
                    {
                        cInternalSubnets = _config.InternalNetworkSubnets.Split(TERMINATOR, StringSplitOptions.RemoveEmptyEntries).ToList<string>();
                    }
                    catch
                    {
                        System.Diagnostics.Trace.WriteLine("Internal network subnets not configured in Security Filter Manager.");
                    }
				}

                // output configuration.
                System.Diagnostics.Trace.WriteLine("\nlockout count: " + cMaxCount.ToString());
                System.Diagnostics.Trace.WriteLine("lockout duration: " + cMaxPeriod.ToString());
                System.Diagnostics.Trace.WriteLine("block unauthorized domains: " + cWhiteList.ToString());
                System.Diagnostics.Trace.WriteLine("block NTLM authentication: " + cBlockNTLM.ToString());
                System.Diagnostics.Trace.WriteLine("enforce device authorization: " + cDeviceAuthorization.ToString());
                System.Diagnostics.Trace.WriteLine("internal network subnets: ");

                if (cEventLog != null)
                {
                    cEventLog.LogInfo("lockout count: " + cMaxCount.ToString());
                    cEventLog.LogInfo("lockout duration: " + cMaxPeriod.ToString());
                    cEventLog.LogInfo("block unauthorized domains: " + cWhiteList.ToString());
                    cEventLog.LogInfo("block NTLM authentication: " + cBlockNTLM.ToString());
                    cEventLog.LogInfo("enforce device authorization: " + cDeviceAuthorization.ToString());
                    cEventLog.LogInfo("internal network subnets: ");
                }

                foreach (string _ip in cInternalSubnets)
                {
                    System.Diagnostics.Trace.WriteLine("\t\t" + _ip);
                    if (cEventLog != null)
                        cEventLog.LogInfo("\t\t" + _ip);
                }

				result = true;
			}
			catch (Exception ex)
			{
				Trace.WriteLine("Please correct the following issue and restart this service.\n\nDatabase: failed to connect to SQL instance or more than one entry exists in the SecurityFilterSettings table\n" + ex.InnerException.Message.ToString());
			}
			return result;
		}

		public void OnRequest(object sender, RequestReceivedEventArgs e)
		{
			string _log_output = null;
			string _callId = this.GetHeaderValue(e.Request, "Call-Id");
			string _from = this.GetHeaderValue(e.Request, "From");
			string _uri = SipUriParser.GetUserAtHost(_from);
			string _via = this.GetHeaderValue(e.Request, "Via");
			string _ip = SipUriParser.GetUserIpAddress(_via);
			string _auth = this.GetHeaderValue(e.Request, "proxy-authorization");
			if (_auth == null)
			{
				_auth = this.GetHeaderValue(e.Request, "authorization");
			}
			if (_auth != null)
			{
				int message_type = 0;
				string _domain = null;
				string _user = null;
				string _username = null;
				string _gss = SipUriParser.GetGSS(_auth);
				string _user_agent = this.GetHeaderValue(e.Request, "User-Agent");
				_log_output = _log_output + "\n\tUser-Agent: " + _user_agent;
				_user_agent = this.ClientType(_user_agent);
				_log_output = _log_output + "\n\tclient type: " + _user_agent;
				if (_auth.Substring(0, 7) == "TLS-DSK")
				{
					try
					{
						string _base64cert = _gss.Substring(20, 1168);
						_log_output = _log_output + "\n\tbase 64 certificate: " + _base64cert;
						X509Certificate2 _cert = new X509Certificate2(Convert.FromBase64String(_base64cert));
						_cert.GetCertHashString();
						string _cert_subject = _cert.Subject;
						if (_cert_subject.Substring(3) == _uri)
						{
							_log_output = _log_output + "\n\tcertificate subject name: " + _uri;
							_username = _uri;
						}
						else
						{
							_log_output = _log_output + "\n\tsubject name: %s" + _cert_subject + "  [Does not match SIP URI]";
						}
						goto IL_586;
					}
					catch
					{
						_log_output += "\n\tcertificate: not found.";
						goto IL_586;
					}
				}
				if (_auth.Substring(0, 4) == "NTLM")
				{
					if (this.cBlockNTLM)
					{
						Response failResponse = e.Request.CreateResponse(403);
						e.ServerTransaction.SendResponse(failResponse);
						try
						{
							using (AccountEntities context = new AccountEntities(this.cEntity.ToString()))
							{
								Log _logEntry = new Log
								{
									Filter = "Security Edge Filter",
									ProtectedService = "Lync 2013 Edge",
									Device = _user_agent,
									IP = _ip,
									Username = _username,
									DateTime = DateTime.Now,
									Status = "Blocked"
								};
								context.Logs.Add(_logEntry);
								context.SaveChanges();
							}
						}
						catch
						{
							_log_output += "\n\tdatabase: failed to write to Logs table";
						}
						this.cEventLog.LogInfo(string.Concat(new string[]
						{
							"<REQUEST>\n\tcaller id: ", _callId,
							"\n\tsip uri: ", _uri,
							"\n\tIP address: ", _ip,
							"\n\tuser: ", _username,
							"\n\tNTLM authentication request BLOCKED\n</REQUEST>"
						}));
						return;
					}
					byte[] _blob = null;
					try
					{
						_blob = Convert.FromBase64String(_gss);
					}
					catch
					{
						_log_output += "\n\n failed to decode base 64 GSS data.";
					}
					if (_blob != null)
					{
						message_type = this.GetDomainUser(_blob, out _domain, out _user);
						if (string.Compare(this.cLogLevel, "verbose", true) == 0)
						{
							object obj = _log_output;
							_log_output = string.Concat(new object[]
							{
								obj,
								"\n\tNTLM message type: ", message_type,
								"\n\tdomain: ", (_domain == null) ? "(empty)" : _domain,
								"\n\tuser: ", (_user == null) ? "(empty)" : _user
							});
						}
						if (_domain != null)
						{
							for (int i = 0; i < this.cAdDomains.Count; i++)
							{
								if (this.cAdDomains[i].domain.CompareTo(_domain) == 0)
								{
									_username = _domain + "\\" + _user;
									break;
								}
							}
							if (_username == null)
							{
								int j = 0;
								while (j < this.cAdDomains.Count)
								{
									if (this.cAdDomains[j].upn.CompareTo(_domain) == 0)
									{
										if (this.cAdDomains[j].domain != null)
										{
											_username = this.cAdDomains[j].domain.ToString() + "\\" + _user;
											break;
										}
										_username = this.cAdDomains[j].upn.ToString() + "\\" + _user;
										break;
									}
									else
									{
										j++;
									}
								}
							}
						}
						else if (_user != null)
						{
							int index = _user.IndexOf('@');
							if (index != -1)
							{
								string _userUPN = _user.Substring(0, index);
								string _domainUPN = _user.Substring(index + 1, _user.Length - index - 1);
								int k = 0;
								while (k < this.cAdDomains.Count)
								{
									if (this.cAdDomains[k].upn.CompareTo(_domainUPN) == 0)
									{
										if (this.cAdDomains[k].domain != null)
										{
											_username = this.cAdDomains[k].domain.ToString() + "\\" + _userUPN;
											break;
										}
										_username = this.cAdDomains[k].upn.ToString() + "\\" + _userUPN;
										break;
									}
									else
									{
										k++;
									}
								}
							}
						}
					}
				}
				else
				{
					this.cEventLog.LogWarning("Authentication protocol: " + _auth.Substring(0, 10).ToString());
				}

				IL_586:
                // client submitted valid domain credentials (i.e. not local computer credentials).
				if (_username != null)
				{
					if (string.Compare(this.cLogLevel, "verbose", true) == 0)
					{
						_log_output = _log_output + "\n\tusername: " + _username;
					}
					try
					{
						using (AccountEntities context2 = new AccountEntities(this.cEntity.ToString()))
						{
							AccountLockout _client = context2.AccountLockouts.FirstOrDefault((AccountLockout c) => c.Username == _username);
							if (_client != null && (long)_client.LockoutCount >= (long)((ulong)this.cMaxCount))
							{
								TimeSpan elapsedTime = new TimeSpan(DateTime.Now.Ticks - _client.LockoutTime.Ticks);
								if (elapsedTime.TotalMinutes < this.cMaxPeriod)
								{
									Response failResponse2 = e.Request.CreateResponse(403);
									e.ServerTransaction.SendResponse(failResponse2);
									Log _logEntry2 = new Log
									{
										Filter = "Security Edge Filter",
										ProtectedService = "Lync 2013 Edge",
										Device = _user_agent,
										IP = _ip,
										Username = _username,
										DateTime = DateTime.Now,
										Status = "Blocked"
									};
									context2.Logs.Add(_logEntry2);
									context2.SaveChanges();
									this.cEventLog.LogError(string.Concat(new object[]
									{
										"<REQUEST>\n\ttimestamp: ", _client.LockoutTime,
										"\n\tcaller id: ", _callId,
										"\n\tsip uri: ", _uri,
										"\n\tIP address: ", _ip,
										"\n\tuser: ", _username,
										"\n\tsign-in BLOCKED\n</REQUEST>"
									}));
									return;
								}
								context2.AccountLockouts.Remove(_client);
								context2.SaveChanges();
							}
						}
					}
					catch
					{
					}
					this.cUsers.Add(_callId, new SecurityEdgeFilter.LyncUser(_username, _user_agent));
					goto IL_9E4;
				}
				if (3 != message_type)
				{
					goto IL_9E4;
				}
				if (!this.cWhiteList)
				{
					_log_output += "\n\tusername: [NULL]\tRestrict Access to corporate issued computers NOT enforced.";
					this.cEventLog.LogWarning(string.Concat(new string[]
					{
						"<REQUEST>\n\tcaller id: ", _callId,
						"\n\tsip uri: ", _uri,
						"\n\tIP address: ", _ip,
						"\n\tuser: ", (_username == null) ? "(empty)" : _username,
						"\n\tdomain: ", (_domain == null) ? "(empty)" : _domain,
						"\n\tINVALID DOMAIN NAME [Restrict Access to corporate issued computers not enforced]\n</REQUEST>"
					}));
					goto IL_9E4;
				}
				Response failResponse3 = e.Request.CreateResponse(403);
				e.ServerTransaction.SendResponse(failResponse3);
				using (AccountEntities context3 = new AccountEntities(this.cEntity.ToString()))
				{
					Log _logEntry3 = new Log
					{
						Filter = "Security Edge Filter",
						ProtectedService = "Lync 2013 Edge",
						Device = _user_agent,
						IP = _ip,
						Username = _domain + "\\" + _user,
						DateTime = DateTime.Now,
						Status = "Blocked"
					};
					context3.Logs.Add(_logEntry3);
					context3.SaveChanges();
				}
				this.cEventLog.LogError(string.Concat(new string[]
				{
					"<REQUEST>\n\tcaller id: ", _callId,
					"\n\tsip uri: ", _uri,
					"\n\tIP address: ", _ip,
					"\n\tuser: ", (_user == null) ? "(empty)" : _user,
					"\n\tdomain: ", (_domain == null) ? "(empty)" : _domain,
					"\n\tsign-in BLOCKED\n</REQUEST>"
				}));
				return;
			}

			IL_9E4:
			if (string.Compare(this.cLogLevel, "verbose", true) == 0)
			{
				_log_output += "\n\t<headers>";
				foreach (Header hdr in e.Request.AllHeaders)
				{
					string text = _log_output;
					_log_output = string.Concat(new string[]
					{
						text, "\n\t\t", hdr.Type.ToString(), ": ", hdr.Value.ToString()
					});
				}
				_log_output = _log_output + "\n\t</headers>\n\t<content>\n\t" + e.Request.Content.ToString() + "\n\t</content>";
				Trace.WriteLine(string.Concat(new string[]
				{
					"<EDGE REQUEST user=", _uri,
					", ip=", _ip,
					", timestamp=", DateTime.Now.ToString(),
					", call-id=", _callId,
					">",
					_log_output,
					"\n</REQUEST>\n\n"
				}));
			}
			e.Request.SimpleProxy = true;
			e.ServerTransaction.EnableForking = false;
			e.ServerTransaction.CreateBranch().SendRequest(e.Request);
		}

		public void OnResponse(object sender, ResponseReceivedEventArgs e)
		{
			string _log_output = null;
			string _callId = this.GetHeaderValue(e.Response, "Call-Id");
			string _from = this.GetHeaderValue(e.Response, "From");
			string _uri = SipUriParser.GetUserAtHost(_from);
			string _via = this.GetHeaderValue(e.Response, "Via");
			string _ip = SipUriParser.GetUserIpAddress(_via);
			string _method = e.Response.AllHeaders.FindFirst(Header.StandardHeaderType.CSeq).Value.Split(new char[] { ' ' })[1];
			string text = _log_output;
			_log_output = string.Concat(new string[]
			{
				text,
				"\n\tMETHOD: ", _method.ToString(),
				"\t\tSTATUS: ", e.Response.StatusCode.ToString()
			});
			if (this.cUsers.ContainsKey(_callId))
			{
				SecurityEdgeFilter.LyncUser _user = this.cUsers[_callId] as SecurityEdgeFilter.LyncUser;
				string _username = _user.GetUsername();
				if (string.Compare(this.cLogLevel, "verbose", true) == 0)
				{
					_log_output = _log_output + "\n\tusername: " + _username;
					_log_output = _log_output + "\n\tclient type: " + _user.GetClientType();
				}
				if (e.Response.StatusCode == 401)
				{
					using (AccountEntities context = new AccountEntities(this.cEntity.ToString()))
					{
						try
						{
							AccountLockout _client = context.AccountLockouts.FirstOrDefault((AccountLockout c) => c.Username == _username);
							AccountLockout expr_1DB = _client;
							expr_1DB.LockoutCount += 1;
							_client.LockoutTime = DateTime.Now;
							context.SaveChanges();
							Log _logEntry = new Log
							{
								Filter = "Security Edge Filter",
								ProtectedService = "Lync 2013 Edge",
								Device = _user.GetClientType(),
								IP = _ip,
								Username = _username,
								DateTime = _client.LockoutTime,
								Status = "Failed",
								FailedLoginCount = (int)_client.LockoutCount
							};
							context.Logs.Add(_logEntry);
							context.SaveChanges();
							this.cEventLog.LogWarning(string.Concat(new object[]
							{
								"<RESPONSE>\n\ttimestamp: ", _client.LockoutTime.ToString(),
								"\n\tResponse: ", e.Response.StatusCode, " ", e.Response.ReasonPhrase,
								"\n\tcaller id: ", _callId,
								"\n\tsip uri: ", _uri,
								"\n\tIP address: ", _ip,
								"\n\tuser: ", (_username == null) ? "(empty)" : _username,
								"\n\tfailed logins: ", _client.LockoutCount.ToString(),
								((long)_client.LockoutCount == (long)((ulong)this.cMaxCount)) ? "\n\tMAXIMUM ALLOWED BAD LOGINS ATTEMPTED" : "",
								"\n</RESPONSE>"
							}));
						}
						catch
						{
							try
							{
								AccountLockout _client2 = new AccountLockout
								{
									Username = _username,
									LockoutCount = 1,
									LockoutTime = DateTime.Now,
									IpAddress = _ip
								};
								context.AccountLockouts.Add(_client2);
								context.SaveChanges();
								Log _logEntry2 = new Log
								{
									Filter = "Security Edge Filter",
									ProtectedService = "Lync 2013 Edge",
									Device = _user.GetClientType(),
									IP = _ip,
									Username = _username,
									DateTime = _client2.LockoutTime,
									Status = "Failed",
									FailedLoginCount = (int)_client2.LockoutCount
								};
								context.Logs.Add(_logEntry2);
								context.SaveChanges();
								this.cEventLog.LogWarning(string.Concat(new object[]
								{
									"<RESPONSE>\n\ttimestamp: ", _client2.LockoutTime.ToString(),
									"\n\tResponse: ", e.Response.StatusCode, " ", e.Response.ReasonPhrase,
									"\n\tcaller id: ", _callId,
									"\n\tsip uri: ", _uri,
									"\n\tIP address: ", _ip,
									"\n\tuser: ", (_username == null) ? "(empty)" : _username,
									"\n\tfailed logins: ", _client2.LockoutCount.ToString(),
									"\n</RESPONSE>"
								}));
							}
							catch (Exception ex)
							{
								this.cEventLog.LogError("Security Filter protection disabled:\n\n\tFailed to connect to database. To troubleshoot this issue, please verify the availability of your SQL Server, possible connectivity issues with your database, or validate your SQL connection string.\n\n" + ex.InnerException.Message.ToString());
							}
						}
						goto IL_75F;
					}
				}
				if (e.Response.StatusCode == 200)
				{
					try
					{
						using (AccountEntities context2 = new AccountEntities(this.cEntity.ToString()))
						{
							AccountLockout _client3 = (from c in context2.AccountLockouts
							where c.Username == _username
							select c).FirstOrDefault<AccountLockout>();
							context2.AccountLockouts.Remove(_client3);
						}
					}
					catch (Exception ex2)
					{
						this.cEventLog.LogError("Failed to delete " + _username + " from database. Database entry may not exist. " + ex2.Message);
					}
					try
					{
						using (AccountEntities context3 = new AccountEntities(this.cEntity.ToString()))
						{
							Log _logEntry3 = new Log
							{
								Filter = "Security Edge Filter",
								ProtectedService = "Lync 2013 Edge",
								Device = _user.GetClientType(),
								IP = _ip,
								Username = _username,
								DateTime = DateTime.Now,
								Status = "Successful",
								FailedLoginCount = 0
							};
							context3.Logs.Add(_logEntry3);
							context3.SaveChanges();
						}
					}
					catch
					{
						_log_output += "\n\tdatabase: failed to write to Logs table";
					}
					if (string.Compare(this.cLogLevel, "verbose", true) == 0)
					{
						_log_output += "\n\tsuccessfully signed in to Lync Server";
					}
				}
				IL_75F:
				this.cUsers.Remove(_callId);
			}
			else
			{
				_log_output += "\n\tusername: (empty)";
				try
				{
					IEnumerator enumerator = e.Response.GetHeaders("via");
					while (enumerator.MoveNext())
					{
						Header via = (Header)enumerator.Current;
						for (int i = 0; i < this.cInternalSubnets.Count; i++)
						{
							if (via.Value.Contains(this.cInternalSubnets[i]))
							{
								_log_output = _log_output + "\n\tHEADER STRIPPED: [" + via.Value + "]";
								e.Response.AllHeaders.Remove(via);
								break;
							}
						}
					}
				}
				catch
				{
					_log_output += "HEADERS [NOT FOUND]\n";
				}
				for (int j = 0; j < this.cInternalSubnets.Count; j++)
				{
					e.Response.Content = this.StripIp(e.Response.Content, this.cInternalSubnets[j]);
				}
			}
			if (string.Compare(this.cLogLevel, "verbose", true) == 0)
			{
				string text2 = _log_output;
				_log_output = string.Concat(new string[]
				{
					text2,
					"\n\tstatus: ", e.Response.StatusCode.ToString(),
					"\n\treason: ", e.Response.ReasonPhrase.ToString(),
					"\n\t<headers>"
				});
				foreach (Header hdr in e.Response.AllHeaders)
				{
					string text3 = _log_output;
					_log_output = string.Concat(new string[]
					{
						text3,
						"\n\t\t", hdr.Type.ToString(), ": ", hdr.Value.ToString()
					});
				}
				_log_output = _log_output + "\n\t</headers>\n\t<content>\n\t" + e.Response.Content.ToString() + "\n\t</content>";
				Trace.WriteLine(string.Concat(new string[]
				{
					"<EDGE RESPONSE user=", _uri,
					", ip=", _ip,
					", timestamp=", DateTime.Now.ToString(),
					", call-id=", _callId,
					">",
					_log_output,
					"\n</RESPONSE>\n\n"
				}));
			}
			e.ClientTransaction.ServerTransaction.SendResponse(e.Response);
		}

		internal string StripIp(string Content, string InternalIP)
		{
			int i = 0;
			string endofline = "\r\n";
			while ((i = Content.IndexOf(InternalIP, i)) != -1)
			{
				int j = Content.LastIndexOf(endofline, i);
				if (j == -1)
				{
					j = 0;
				}
				i = Content.IndexOf(endofline, i);
				if (i != -1)
				{
					int size = i - j;
					Content = Content.Remove(j, size);
					i = j;
				}
			}
			return Content;
		}

		internal string GetHeaderValue(Message Msg, string Hdr)
		{
			try
			{
				IEnumerator walker = Msg.GetHeaders(Hdr);
				walker.MoveNext();
				if (walker.Current != null)
				{
					return ((Header)walker.Current).Value;
				}
			}
			catch
			{
			}
			return null;
		}

		public string ClientType(string useragent)
		{
			string _type = "unavailable";
			if (!string.IsNullOrEmpty(useragent))
			{
				if (useragent.Contains("Microsoft Lync for Mac"))
				{
					_type = "Lync for Mac";
				}
				else if (useragent.Contains("Microsoft Lync"))
				{
					_type = "Lync for Windows";
				}
			}
			return _type;
		}

		public int GetDomainUser(byte[] blob, out string domain, out string username)
		{
            // structure of NTLM message type 3: AUTHENTICATE_MESSAGE.
            //private const string NTLM_SIGNATURE = "NTLMSSP";

            //public enum NTLM_MESSAGE_TYPE : int { 
            //    NtLmNegotiate = 1, 
            //    NtLmChallenge, 
            //    NtLmAuthenticate, 
            //    NtLmUnknown 
            //};

            //[StructLayout(LayoutKind.Explicit, Size = 8)]
            //public struct STRING32
            //{
            //    [FieldOffset(0)]
            //    ushort Length;
            //    [FieldOffset(2)]
            //    ushort MaximumLength;
            //    [FieldOffset(4)]
            //    uint Buffer;
            //};

            //[StructLayout(LayoutKind.Explicit, Size = 86)]
            //public unsafe struct AUTHENTICATE_MESSAGE
            //{
            //    [FieldOffset(0)]
            //    byte[] Signature;
            //    [FieldOffset(8)]
            //    int MessageType;
            //    [FieldOffset(12)]
            //    void* LmChallengeResponse;
            //    [FieldOffset(20)]
            //    void* NtChallengeResponse;
            //    [FieldOffset(28)]
            //    void* DomainName;
            //    [FieldOffset(36)]
            //    void* UserName;
            //    [FieldOffset(42)]
            //    void* Workstation;
            //    [FieldOffset(50)]
            //    void* SessionKey;
            //    [FieldOffset(58)]
            //    uint NegotiateFlags;
            //    [FieldOffset(62)]
            //    double Version;
            //    [FieldOffset(70)]
            //    byte[] HandShakeMessagesMIC;
            //};
			int _message_type = 0;
			domain = null;
			username = null;
			try
			{
                // AUTHENTICATE_MESSAGE parameters of type STRING32 are Unicode strings.
				Encoding encoding = new UnicodeEncoding();
                // NTLM message type 3.
				_message_type = (int)blob[8];

				if (3 == _message_type)
				{
                    // offset and length of domain name (see above for details of data structure).
                    int offset = 0;
					int length = (int)blob[28];

					if (length > 0)
					{
						offset = (int)blob[32] + (256 * blob[33]); 
						// domain name. 
						domain = encoding.GetString(blob, offset, length).ToLower();
					}

                    // offset and length of user name (see above for details of data structure).
					length = (int)blob[36];

					if (length > 0)
					{
						offset = (int)blob[40] + (256 * blob[41]);
						// username.
						username = encoding.GetString(blob, offset, length).ToLower();
					}
				}
			}
			catch
			{
				domain = null;
				username = null;
			}
			return _message_type;
		}
	}
}
