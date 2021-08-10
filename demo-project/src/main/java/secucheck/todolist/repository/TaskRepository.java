package secucheck.todolist.repository;

import org.springframework.data.repository.CrudRepository;

import secucheck.todolist.model.Task;

public interface TaskRepository extends CrudRepository<Task, Long> {

}