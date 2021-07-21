namespace SimpleDnsCrypt.Utils.Models
{
    public class Stamp
    {
        public StampProtocol Protocol { get; set; }
        public StampProperties Properties { get; set; }
        public string Address { get; set; }
        public string PublicKey { get; set; }
        public string ProviderName { get; set; }
        public string Hash { get; set; }
        public string Hostname { get; set; }
        public string Path { get; set; }
        public int Port { get; set; }
        public bool IsValid
        {
            get
            {
                if (Protocol == StampProtocol.DnsCrypt)
                {
                    return !string.IsNullOrEmpty(Address) &&
                           !string.IsNullOrEmpty(PublicKey);
                }

                if (Protocol == StampProtocol.DoH)
                {
                    return !string.IsNullOrEmpty(Hash) &&
                           !string.IsNullOrEmpty(Hostname);
                }

                if (Protocol == StampProtocol.DNSCryptRelay)
                {
                    return true;
                }

                return false;
            }
        }
    }
}
