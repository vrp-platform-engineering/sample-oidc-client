using Microsoft.IdentityModel.Logging;
using oidc.client.mvc.code.flow.Support.IOC;

namespace oidc.client.mvc.code.flow
{
    public class Startup
    {
        #region ...

        public Startup(IConfiguration configuration)
        {
            Configuration = configuration;
        }

        public IConfiguration Configuration { get; }

        #endregion

        public void ConfigureServices(IServiceCollection services)
        {
            services.AddAuthenticationSupport(this.Configuration);

            services.AddHttpContextAccessor();
            services.AddControllersWithViews();
            services.AddRazorPages();
        }

        public void Configure(IApplicationBuilder app, IWebHostEnvironment env)
        {
            IdentityModelEventSource.ShowPII = true;

            if (env.IsDevelopment())
            {
                app.UseDeveloperExceptionPage();
            }
            else
            {
                app.UseExceptionHandler("/Error");
                app.UseHsts();
            }

            app.UseHttpsRedirection();
            app.UseStaticFiles();

            app.UseRouting();

            app.UseAuthentication();
            app.UseAuthorization();

            app.UseEndpoints(endpoints =>
            {
                // Map attribute-routed controllers (including signout-callback-oidc)
                endpoints.MapControllers();
                
                // Map conventional routes (with authorization required)
                endpoints.MapControllerRoute(
                    name: "default",
                    pattern: "{controller=Home}/{action=Index}/{id?}")
                    .RequireAuthorization();

                endpoints.MapRazorPages();
            });
        }
    }
}
