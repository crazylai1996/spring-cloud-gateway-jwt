package gdou.laiminghai.jwtclient;

import gdou.laiminghai.jwtclient.filter.CurrentUserResolver;
import org.springframework.boot.SpringApplication;
import org.springframework.cloud.client.SpringCloudApplication;
import org.springframework.web.method.support.HandlerMethodArgumentResolver;
import org.springframework.web.servlet.config.annotation.WebMvcConfigurer;

import java.util.List;

@SpringCloudApplication
public class JwtClientApplication implements WebMvcConfigurer {

	public static void main(String[] args) {
		SpringApplication.run(JwtClientApplication.class, args);
	}

	public void addArgumentResolvers(List<HandlerMethodArgumentResolver> argumentResolvers) {
		argumentResolvers.add(new CurrentUserResolver());
	}

}

