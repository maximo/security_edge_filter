using System.ServiceProcess;

namespace security_edge_filter
{
    static class Program
    {
        /// <summary>
        /// The main entry point for the application.
        /// </summary>
        static void Main()
        {
            ServiceBase[] ServicesToRun = new ServiceBase[]
			{ 
				new security_filter_svc() 
			};
            ServiceBase.Run(ServicesToRun);
        }
    }
}
