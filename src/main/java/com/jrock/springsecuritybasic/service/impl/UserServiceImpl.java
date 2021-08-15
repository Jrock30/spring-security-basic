package com.jrock.springsecuritybasic.service.impl;

import com.jrock.springsecuritybasic.domain.Account;
import com.jrock.springsecuritybasic.repository.UserRepository;
import com.jrock.springsecuritybasic.service.UserService;
import org.springframework.beans.factory.annotation.Autowired;
import org.springframework.stereotype.Service;
import org.springframework.transaction.annotation.Transactional;

@Service("userService")
public class UserServiceImpl implements UserService {

    @Autowired
    private UserRepository userRepository;

    @Transactional
    @Override
    public void createUser(Account account) {
        userRepository.save(account);
    }
}
