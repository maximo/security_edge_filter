using Lync.Utils;
using Microsoft.Rtc.Sip;
using System;
using System.Configuration;
using System.Data.EntityClient;
using System.Data.SqlClient;
using System.Diagnostics;
using System.ServiceProcess;
using System.Threading;

namespace security_edge_filter
{
	public partial class security_filter_svc : ServiceBase
	{
		private bool cancel;
		internal AppEventLog logger;
		private SecurityEdgeFilter edgefilter;
		private string manifest;
        private EntityConnectionStringBuilder entity;

		public security_filter_svc()
		{
			this.InitializeComponent();
			this.cancel = false;
			this.logger = new AppEventLog(base.ServiceName, "Application");
            entity = new EntityConnectionStringBuilder();
		}

		protected override void OnStart(string[] args)
		{
			string customer = "CBA";
            string licenses = "2";
            string version = "version 2.8";

			if (customer == null)
			{
				DateTime _expiration = new DateTime(2020, 8, 1, 1, 0, 0);
				if (DateTime.Compare(DateTime.Now, _expiration) >= 0)
				{
					this.logger.LogError("This trial version of Security Edge Filter has expired. Please contact www.security-filters.com to purchase a license.");
					base.Stop();
					return;
				}
			}
			string _level = "normal";
			string install_path;
			try
			{
				entity.Provider = ConfigurationManager.ConnectionStrings["db"].ProviderName;
				entity.ProviderConnectionString = ConfigurationManager.ConnectionStrings["db"].ConnectionString;
				entity.Metadata = "res://*/SecurityFilterManager.csdl|res://*/SecurityFilterManager.ssdl|res://*/SecurityFilterManager.msl";
				if (ConfigurationManager.AppSettings["logLevel"] != "")
				{
					_level = ConfigurationManager.AppSettings["logLevel"];
				}
				install_path = ConfigurationManager.AppSettings["path"];
			}
			catch (Exception ex)
			{
				this.logger.LogError("Failed to read configuration.\n\nError: " + ex.Message);
				base.Stop();
				return;
			}
            string copyright = "Copyright (c) 2010-2017 MB Corporation. All rights reserved. De-compilation, reproduction or reverse engineering is strictly prohibited.\n\n"; 

			if (!string.IsNullOrEmpty(customer))
			{
                string text = copyright;
				copyright = string.Concat(new string[]
				{
			        text,
                    version, 
                    "\n\nThe Security Edge Filter Enterprise Edition is expressly licensed to ",
					customer, " for use on ", licenses, " Edge Server(s).\nTo purchase licenses, please contact www.security-filters.com."
				});
			}
			this.logger.LogInfo(string.Concat(new string[]
			{
				copyright,
				"Service: ", base.ServiceName,
				"\nLogging level: ", _level
			}));
			Trace.WriteLine(string.Concat(new string[]
			{
				copyright,
				"Service: ", base.ServiceName,
				"\nLogging level: ", _level
			}));

            // start SQL Server query notifications.
            SqlDependency.Start(entity.ProviderConnectionString);

			this.edgefilter = new SecurityEdgeFilter(entity, this.logger, _level);
			this.manifest = install_path + "security_filter.am";
			new Thread(new ThreadStart(this.RunFilter)) { IsBackground = true }.Start();
		}

		protected override void OnStop()
		{
			this.cancel = true;

            // stop SQL Server query notifications.
            SqlDependency.Stop(entity.ProviderConnectionString);
		}

		private void RunFilter()
		{
			try
			{
				ServerAgent _agent = ConnectToServer(this.edgefilter, this.manifest, this.logger);
				if (_agent != null)
				{
					while (!this.cancel)
					{
						_agent.WaitHandle.WaitOne();
						ThreadPool.QueueUserWorkItem(new WaitCallback(_agent.ProcessEvent));
					}
				}
				else
				{
					this.logger.LogError("Unable to register with Edge Server. Ensure it is running and restart this service.");
				}
			}
			catch
			{
				this.logger.LogError("Edge Server is unresponsive. Ensure it is running and restart this service.");
			}
			base.Stop();
		}

		private ServerAgent ConnectToServer(object app, string amFile, AppEventLog eventLog)
		{
			ServerAgent result = null;
			try
			{
				ServerAgent.WaitForServerAvailable(1000);
			}
			catch (Exception e)
			{
				eventLog.LogError("ERROR: Server unavailable - " + e.Message);
				if (e is UnauthorizedException)
				{
					eventLog.LogError("Service must be running under an account that is a member of the \"RTC Server Applications\" local group");
				}
				return result;
			}
			ApplicationManifest am = ApplicationManifest.CreateFromFile(amFile);
			if (am == null)
			{
				eventLog.LogError("ERROR: " + amFile + " application manifest file not found.");
				return result;
			}
			try
			{
				am.Compile();
			}
			catch (CompilerErrorException e2)
			{
				eventLog.LogError("ERROR: " + amFile + " application manifest file contained errors:");
				foreach (string message in e2.ErrorMessages)
				{
					eventLog.LogError(message);
				}
				return result;
			}
			try
			{
				ServerAgent agent = new ServerAgent(app, am);
				result = agent;
			}
			catch (NullReferenceException nre)
			{
				eventLog.LogError("ServerAgent cannot be instantiated.\n" + nre.InnerException.Message);
				result = null;
			}
			catch (ServerNotFoundException snfe)
			{
				eventLog.LogError("Microsoft Lync Edge Server is not available." + snfe.InnerException.Message);
				result = null;
			}
			catch (Exception e3)
			{
				eventLog.LogError(string.Concat(new string[]
				{
					"ERROR: Unable to connect to server - ", e3.InnerException.Message, "\n",
					e3.ToString(), "\n",
					e3.StackTrace
				}));
				result = null;
			}
			return result;
		}
	}
}
