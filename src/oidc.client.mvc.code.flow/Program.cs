namespace oidc.client.mvc.code.flow
{
    public class Program
    {
        public static void Main(string[] args)
        {
            Console.Title = "client.mvc.code.flow";
            CreateHostBuilder(args).Build().Run();
        }

        public static IHostBuilder CreateHostBuilder(string[] args) =>
            Host.CreateDefaultBuilder(args)
                .ConfigureWebHostDefaults(webBuilder =>
                {
                    webBuilder.UseStartup<Startup>();
                });
    }
}
