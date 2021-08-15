package com.jrock.springsecuritybasic.repository;

import com.jrock.springsecuritybasic.domain.Account;
import org.springframework.data.jpa.repository.JpaRepository;

public interface UserRepository extends JpaRepository<Account, Long> {

}
