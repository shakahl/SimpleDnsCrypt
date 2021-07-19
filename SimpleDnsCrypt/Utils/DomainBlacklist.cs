using System;
using System.Collections.Generic;
using System.IO;
using System.Net.Http;
using System.Text;
using System.Text.RegularExpressions;
using System.Threading.Tasks;

namespace SimpleDnsCrypt.Utils
{
	public static class DomainBlacklist
	{
		public static async Task<SortedSet<string>> Build(List<string> blacklistsSource, List<string> whitelistSource = null)
		{
			var blacklist = new SortedSet<string>();
			var whitelist = new SortedSet<string>(whitelistSource);
			foreach (var blacklistSourceEntry in blacklistsSource)
			{
				if (blacklistSourceEntry.StartsWith("file:"))
				{
					var filename = blacklistSourceEntry.Split(new[] { "file:" }, StringSplitOptions.None)[1];
					if (string.IsNullOrEmpty(filename)) continue;
					if (!File.Exists(filename)) continue;
					var rawListString = await File.ReadAllLinesAsync(filename);
					var parsed = ParseBlacklist(rawListString, true);
					foreach (var p in parsed)
					{
						blacklist.Add(p);
					}
				}
				else
				{
					var rawListString = await FetchRemoteListAsync(blacklistSourceEntry);
					if (rawListString == null) continue;
					var parsed = ParseBlacklist(rawListString, false);
					foreach (var p in parsed)
					{
						blacklist.Add(p);
					}
				}
			}

			blacklist.ExceptWith(whitelist);
			return blacklist;
		}

		private static async Task<string> FetchRemoteListAsync(string requestUri)
		{
			try
			{
				using (var client = new HttpClient())
				{
					var getDataTask = client.GetStringAsync(requestUri);
					return await getDataTask.ConfigureAwait(false);
				}
			}
			catch (Exception)
			{

			}
			return null;
		}

		public static IEnumerable<string> ParseBlacklist(string blacklist, bool trusted = false)
		{
			var lines = blacklist.Split(new[] { '\r', '\n' }, StringSplitOptions.RemoveEmptyEntries);
			return ParseBlacklist(lines, trusted);
		}

		public static IEnumerable<string> ParseBlacklist(IEnumerable<string> lines, bool trusted = false)
		{
			var names = new List<string>();
			var rxComment = new Regex(@"^(#|$)");
			var rxU = new Regex(@"^@*\|\|([a-z0-9.-]+[.][a-z]{2,})\^?(\$(popup|third-party))?$");
			var rxL = new Regex(@"^([a-z0-9.-]+[.][a-z]{2,})$");
			var rxH = new Regex(@"^[0-9]{1,3}[.][0-9]{1,3}[.][0-9]{1,3}[.][0-9]{1,3}\s+([a-z0-9.-]+[.][a-z]{2,})$");
			var rxMdl = new Regex(@"^""[^""]+"",""([a-z0-9.-]+[.][a-z]{2,})"",");
			var rxB = new Regex(@"^([a-z0-9.-]+[.][a-z]{2,}),.+,[0-9: /-]+,");
			var rxTrusted = new Regex(@"^([*a-z0-9.-]+)$");

			foreach (var line in lines)
			{
				var tmp = line.ToLower().Trim();
				var regexList = new List<Regex>();
				if (trusted)
				{
					regexList.Add(rxTrusted);
				}
				else
				{
					regexList.Add(rxU);
					regexList.Add(rxL);
					regexList.Add(rxH);
					regexList.Add(rxMdl);
					regexList.Add(rxB);
				}

				var isComment = rxComment.Match(tmp);
				if (isComment.Success)
				{
					continue;
				}

				foreach (var regex in regexList)
				{
					var isMatching = regex.Match(tmp);
					if (!isMatching.Success)
					{
						continue;
					}
					if (!names.Contains(isMatching.Groups[1].Value))
					{
						names.Add(isMatching.Groups[1].Value);
					}
				}
			}
			return names;
		}
	}
}