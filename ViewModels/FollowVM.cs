using socset.DataLayer;

namespace socset.ViewModels
{
    public class FollowVM
    {
        public ApplicationUser User { get; set; }
        public List<ApplicationUser> Followers { get; set; }
        public List<ApplicationUser> Following { get; set; }
    }
}
