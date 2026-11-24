
using cryptium_backend.Services;

namespace cryptium_backend
{
    public class Program
    {
        public static void Main(string[] args)
        {
            if (args.Contains("--run-tests"))
            {
                int failed = CryptoTests.RunAll();
                Environment.Exit(failed == 0 ? 0 : 1);
                return;
            }

            var builder = WebApplication.CreateBuilder(args);

            builder.Services.AddCors(options =>
            {
                options.AddPolicy("CryptiumPolicy", policy =>
                {
                    policy
                        .WithOrigins("http://localhost:5173")
                        .AllowAnyHeader()
                        .AllowAnyMethod();
                });
            });

            builder.Services.AddScoped<CryptoService>();
            builder.Services.AddScoped<FileCryptoService>();
            builder.Services.AddScoped<AnalysisService>();
            builder.Services.AddScoped<MalwareScanService>();
            builder.Services.AddScoped<AudioSteganographyService>();

            // Add services to the container.

            builder.Services.AddControllers();
            // Learn more about configuring Swagger/OpenAPI at https://aka.ms/aspnetcore/swashbuckle
            builder.Services.AddEndpointsApiExplorer();
            builder.Services.AddSwaggerGen();

            var app = builder.Build();
            app.UseCors("CryptiumPolicy");

            // Configure the HTTP request pipeline.
            if (app.Environment.IsDevelopment())
            {
                app.UseSwagger();
                app.UseSwaggerUI();
            }

            app.UseHttpsRedirection();

            app.UseAuthorization();


            app.MapControllers();

            app.Run();
        }
    }
}
