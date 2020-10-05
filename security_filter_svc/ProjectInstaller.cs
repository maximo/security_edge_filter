using System;
using System.Collections;
using System.ComponentModel;
using System.Configuration;
using System.Configuration.Install;
using System.Data.SqlClient;
using System.IO;
using System.ServiceProcess;

namespace security_edge_filter
{
	[RunInstaller(true)]
	public partial class ProjectInstaller : Installer
	{
		private string serviceName;

		public ProjectInstaller()
		{
			this.serviceName = "Security Edge Filter";
			this.InitializeComponent();
		}

		public override void Uninstall(IDictionary stateSaver)
		{
			ServiceController _controller = new ServiceController("Security Edge Filter");
			try
			{
				if (_controller.Status == ServiceControllerStatus.Running | _controller.Status == ServiceControllerStatus.Paused)
				{
					_controller.Stop();
					_controller.WaitForStatus(ServiceControllerStatus.Stopped, new TimeSpan(0, 0, 0, 15));
					_controller.Close();
				}
			}
			catch
			{
			}
			finally
			{
				base.Uninstall(stateSaver);
				string _configFileName = base.Context.Parameters["assemblypath"];
				ConfigurationManager.OpenExeConfiguration(_configFileName);
				string config_file = _configFileName + ".config";
				if (File.Exists(config_file))
				{
					try
					{
						File.Delete(config_file);
					}
					catch
					{
					}
				}
			}
		}

		public override void Install(IDictionary stateSaver)
		{
			base.Install(stateSaver);
			string _configFileName = base.Context.Parameters["assemblypath"];
			Configuration _config = ConfigurationManager.OpenExeConfiguration(_configFileName);
			SqlConnectionStringBuilder _sql = new SqlConnectionStringBuilder();
			_sql.DataSource = base.Context.Parameters["db"].ToString();
			try
			{
				_sql.FailoverPartner = base.Context.Parameters["db_failover"].ToString();
			}
			catch
			{
			}
			_sql.ConnectTimeout = 10;
			_sql.InitialCatalog = "SecurityFilterManager";
			_sql.MultipleActiveResultSets = true;
			_sql.UserID = base.Context.Parameters["account"].ToString();
			_sql.Password = base.Context.Parameters["password"].ToString();
			string providerName = "System.Data.SqlClient";
			ConnectionStringsSection connectionSection = _config.ConnectionStrings;
			if (connectionSection == null)
			{
				connectionSection = new ConnectionStringsSection();
				_config.Sections.Add("connectionSettings", connectionSection);
			}
			if (!connectionSection.SectionInformation.IsProtected)
			{
				connectionSection.SectionInformation.ProtectSection("DataProtectionConfigurationProvider");
			}
			try
			{
				connectionSection.ConnectionStrings["db"].Name = "db";
				connectionSection.ConnectionStrings["db"].ConnectionString = _sql.ToString();
				connectionSection.ConnectionStrings["db"].ProviderName = providerName;
			}
			catch
			{
				connectionSection.ConnectionStrings.Add(new ConnectionStringSettings("db", _sql.ToString(), providerName));
			}
			string install_path = base.Context.Parameters["installdir"].ToString();
			install_path = install_path.Remove(install_path.Length - 1, 1);
			try
			{
				_config.AppSettings.Settings["path"].Value = install_path;
			}
			catch
			{
				_config.AppSettings.Settings.Add("path", install_path);
			}
			try
			{
				_config.AppSettings.Settings["logLevel"].Value = "verbose";
			}
			catch
			{
				_config.AppSettings.Settings.Add("logLevel", "verbose");
			}
			_config.Save(ConfigurationSaveMode.Modified);
			ServiceController _controller = new ServiceController(this.serviceName);
			try
			{
                // start service.
                // _controller.Start();
			}
			finally
			{
				_controller.Dispose();
			}
		}
	}
}
