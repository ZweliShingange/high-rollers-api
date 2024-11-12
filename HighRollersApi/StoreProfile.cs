using AutoMapper;
using HighRollersApi;

public class StoreProfile : Profile
{
    public StoreProfile()
    {
        CreateMap<CustomerDto, Customer>();            
        CreateMap<Customer, CustomerDto>();            
        CreateMap<CustomerFilterDto, Customer>();
        CreateMap<AdminDto, Admin>()
            .ForMember(dest => dest.PasswordHash, opt => opt.Ignore());
        CreateMap<Admin, AdminDto>();
    }
}