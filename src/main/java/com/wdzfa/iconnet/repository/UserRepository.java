package com.wdzfa.iconnet.repository;

import com.wdzfa.iconnet.model.User;
import org.springframework.data.repository.CrudRepository;

import java.util.Optional;

public interface UserRepository extends CrudRepository<User, Long> {

    Optional<User> findByEmail(String email);

    User findByRefreshToken(String refreshToken);

}
