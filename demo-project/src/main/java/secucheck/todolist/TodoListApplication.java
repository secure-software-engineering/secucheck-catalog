package secucheck.todolist;

import org.springframework.boot.SpringApplication;
import org.springframework.boot.autoconfigure.SpringBootApplication;
import org.springframework.boot.context.properties.EnableConfigurationProperties;

import secucheck.todolist.service.StorageProperties;

@SpringBootApplication
@EnableConfigurationProperties(StorageProperties.class)
public class TodoListApplication {

	public static void main(String[] args) {
		SpringApplication.run(TodoListApplication.class, args);
	}

}
