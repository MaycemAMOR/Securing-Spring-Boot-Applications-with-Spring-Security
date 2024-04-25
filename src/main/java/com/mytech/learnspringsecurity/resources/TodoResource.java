package com.mytech.learnspringsecurity.resources;

import jakarta.annotation.security.RolesAllowed;
import org.slf4j.Logger;
import org.slf4j.LoggerFactory;
import org.springframework.security.access.annotation.Secured;
import org.springframework.security.access.prepost.PostAuthorize;
import org.springframework.security.access.prepost.PreAuthorize;
import org.springframework.web.bind.annotation.*;

import java.util.List;

@RestController
public class TodoResource {

    private final Logger logger = LoggerFactory.getLogger(TodoResource.class);
    List<Todo> todos = List.of(
            new Todo("MayTech", "Learn Aws"),
            new Todo("MayTech", "Visit USA"),
            new Todo("MayTech", "Learn dancing"),
            new Todo("MayTech", "Learn drive a car"),
            new Todo("MayTech", "Get AWS Certified")
    );

    @GetMapping("/todos")
    public List<Todo> retrieveAllTodos() {
        return todos;
    }

    @GetMapping("users/{username}/todos")
    @PreAuthorize("hasRole('USER') and #username == authentication.name")
    @PostAuthorize("returnObject.username == 'MayTech'")
    @RolesAllowed({"ADMIN", "USER"})
    @Secured({"ROLE_ADMIN", "ROLE_USER"})
    public Todo retrieveTodosForSpecificUser(@PathVariable String username) {
        //return todos.stream().filter(todo -> todo.username().equals(username)).collect(Collectors.toList());
        return todos.get(0);
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

