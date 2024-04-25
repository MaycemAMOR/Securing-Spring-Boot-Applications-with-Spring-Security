package com.mytech.learnspringsecurity.resources;

import org.slf4j.Logger;
import org.slf4j.LoggerFactory;
import org.springframework.web.bind.annotation.*;

import java.util.List;
import java.util.stream.Collectors;

@RestController
public class TodoResource {

    List<Todo> todos = List.of(
            new Todo("MayTech", "Learn Aws"),
            new Todo("MayTech", "Visit USA"),
            new Todo("MayTech", "Learn dancing"),
            new Todo("MayTech", "Learn drive a car"),
            new Todo("MayTech", "Get AWS Certified")
    );
    private final Logger logger = LoggerFactory.getLogger(TodoResource.class);

    @GetMapping("/todos")
    public List<Todo> retrieveAllTodos() {
        return todos;
    }

    @GetMapping("users/{username}/todos")
    public List<Todo> retrieveTodosForSpecificUser(@PathVariable String username) {
        return todos.stream().filter(todo -> todo.username().equals(username)).collect(Collectors.toList());
    }

    @PostMapping("users/{username}/todos")
    public Todo createTodosForSpecificUser(@PathVariable String username, @RequestBody Todo todo) {
        logger.info("Create {} to {}", todo, username);
        Todo createdTodo = new Todo(todo.username(), todo.description());
        return createdTodo;
    }


}

record Todo(String username, String description) {
}

