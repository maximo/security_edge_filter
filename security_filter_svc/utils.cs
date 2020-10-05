using System;
using System.Diagnostics;

namespace Lync.Utils
{
	#region URIParser

	/// <summary>
	/// A simple utility class to parse SIP From and To headers,
	/// and extract the user@host uri
	/// </summary>
	public class SipUriParser
	{

		/// <summary>
		/// Parse a SIP address header (specifically From or To)
		/// and return the user@host 
		/// </summary>
		/// <returns>user@host if parsable, null if not</returns>
		public static string GetUserAtHost(string sipAddressHeader)
		{
			if (sipAddressHeader == null) return null;
			
			string uri = null;

			/// If the header has < > present, then extract the uri
			/// else treat the input as uri
			int index1 = sipAddressHeader.IndexOf('<');

			if (index1 != -1)
			{	
				int index2 = sipAddressHeader.IndexOf('>');
				///address, extract uri
				uri = sipAddressHeader.Substring(index1 + 1, index2 - index1 - 1);
			}
			else
			{
				uri = sipAddressHeader;
			}
	
			///chop off all parameters. we assume that there is no
			///semicolon in the user part (which is allowed in some cases!)
			index1 = uri.IndexOf(';');
			if (index1 != -1)
			{
				uri = uri.Substring(0, index1 - 1);
			}

            // lowercase string.
            uri = uri.ToLower();

			///we will process only SIP uri (thus no sips or tel)
			///and wont accept those without user names
			if (uri.StartsWith("sip:") == false || 
				uri.IndexOf('@') == -1) 
				return null;
			
			///now we have sip:user@host most likely, with some exceptions that
			/// are ignored
			///  1) user part contains semicolon separated user parameters
			///  2) user part also has the password (as in sip:user:pwd@host)
			///  3) some hex escaped characters are present in user part
			///  4) the host part also has the port (Contact header for example)

			return uri.Substring("sip:".Length /* uri.Substring(4) */);
		}

        public static string GetUserIpAddress(string viaHeader)
        {
            if (viaHeader == null) return null;
            
            string ipAddress = null;
            string tag = "received=";

            int index = viaHeader.IndexOf(tag);

            if (index != -1)
            {
                ipAddress = viaHeader.Substring(index + tag.Length);

                index = ipAddress.IndexOf(';');
                if (index != -1)
                {
                    return ipAddress.Substring(0, index);
                }
            }

            return ipAddress;
        }

        public static string GetGSS(string proxyAuthorization)
        {
            string gssData;

            try
            {
                // find beginning of gssapi-data field.
                int index = proxyAuthorization.IndexOf("gssapi-data=") + 13;
                // remove beginning of string until start of gssapi-data.
                gssData = proxyAuthorization.Substring(index);
                // find index of gssapi-data field.
                index = gssData.IndexOf("\"");
                // truncate end of value.
                gssData = gssData.Remove(index);
            }
            catch
            {
                gssData = null;
            }
            return gssData;
        }
	}

	#endregion URIParser

    #region EventLogHelper
    public class AppEventLog
    {
        public static void RegisterEventSource (string eventLogSource, string eventLogTarget)
        {
            if (!EventLog.SourceExists (eventLogSource)) {
                EventLog.CreateEventSource (eventLogSource, eventLogTarget);
            }
        }

        public static void UnregisterEventSource (string eventLogSource)
        {
            if (EventLog.SourceExists (eventLogSource)) {
                EventLog.DeleteEventSource (eventLogSource);
            }
        }

        public AppEventLog (string eventLogSource, string eventLogTarget)
        {
            try
            {
                if (!EventLog.SourceExists (eventLogSource)) {
                    EventLog.CreateEventSource (eventLogSource, eventLogTarget);
                }

                this.eventLog = new EventLog (eventLogTarget);
                this.eventLog.Source = eventLogSource;
            }
            catch
            {
                System.Diagnostics.Trace.WriteLine("Security Filter: insufficient permissions to write to Application Event Viewer.");
            }
        }

        public void Log (EventLogEntryType type, string message)
        {
            if (eventLog != null) {
                eventLog.WriteEntry (message, type);
            }
        }

        public void LogInfo (string message)
        {
            Log (EventLogEntryType.Information, message);
        }

        public void LogError (string message)
        {
            Log (EventLogEntryType.Error, message);
        }

        public void LogWarning (string message)
        {
            Log (EventLogEntryType.Warning, message);
        }

        EventLog eventLog;
    };

    /// <summary>
    /// An event log throttle helps throttle all events of same type. It
    /// ensures that events are logged at a rate not exceeding the configured rate.
    /// </summary>
    public class EventLogThrottle
    {
        public EventLogThrottle (AppEventLog eventLog)
        {
            this.eventLog = eventLog;
            this.duration = EventLogThrottle.DefaultThrottleTime;
            this.lastWrite = DateTime.MinValue;
        }

        /// <summary>
        /// 
        /// </summary>
        /// <param name="duration">Value in minutes. One event per duration will be allowed.</param>
        public EventLogThrottle (AppEventLog eventLog, int duration)
        {
            this.eventLog = eventLog;
            this.duration = duration;
            this.lastWrite = DateTime.MinValue;
        }

        public void LogWarning (string message)
        {
            Log (EventLogEntryType.Warning, message);
        }

        public void LogError (string message)
        {
            Log (EventLogEntryType.Error, message);
        }

        public void Log (EventLogEntryType type, string message)
        {
            DateTime time = DateTime.Now;

            lock (this) {
                TimeSpan elapsed = time - lastWrite;
                if (elapsed.TotalMinutes > duration) {
                    lastWrite = time;
                    eventLog.Log (type, message);
                }
            }
        }

        private AppEventLog eventLog;
        public const int DefaultThrottleTime = 30; // 30 Minutes per event.
        private int duration;
        private DateTime lastWrite;
    }
    #endregion
}
