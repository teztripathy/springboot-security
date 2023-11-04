package com.training.springbootsecurity.todos;

import java.util.List;
import java.util.function.Predicate;

import org.slf4j.Logger;
import org.slf4j.LoggerFactory;
import org.springframework.security.access.annotation.Secured;
import org.springframework.security.access.prepost.PostAuthorize;
import org.springframework.security.access.prepost.PreAuthorize;
import org.springframework.web.bind.annotation.GetMapping;
import org.springframework.web.bind.annotation.PathVariable;
import org.springframework.web.bind.annotation.PostMapping;
import org.springframework.web.bind.annotation.RequestBody;
import org.springframework.web.bind.annotation.RestController;

import jakarta.annotation.security.RolesAllowed;

@RestController
public class TodoResource {
    private Logger logger = LoggerFactory.getLogger(getClass());

    
    private List<Todo> todos = List.of(new Todo("tejeswar", "Learn Fullstack"),
                        new Todo("archana", "Learn Go lang"));

    @GetMapping("/todos")
    @PreAuthorize("hasRole('ADMIN')")
    public List<Todo> retrieveTodos() {
        return this.todos;
    }

    @GetMapping("/todos/{username}")
    @PreAuthorize("hasRole('USER') and #username == authentication.name")
    @PostAuthorize("returnObject[0].username == authentication.name")
    @RolesAllowed({"ADMIN", "USER"}) //Redundancy
    @Secured({"ROLE_ADMIN", "ROLE_USER"}) //More redundancey, this checkes the Authority
    public List<Todo> retrieveTodosPerUser(@PathVariable String username) {
        
        Predicate<? super Todo> predicate = todo -> todo.username().equals(username);
        return this.todos.stream().filter(predicate).toList();
    }

    @PostMapping("/todos")
    public void addTodoPerUser(@RequestBody Todo todo) {
        //this.todos.add(todo);
        logger.info("Create {} for {}", todo, todo);
    }
}
