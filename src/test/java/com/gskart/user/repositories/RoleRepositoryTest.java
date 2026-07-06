package com.gskart.user.repositories;

import com.gskart.user.entities.Role;
import org.junit.jupiter.api.Test;
import org.springframework.beans.factory.annotation.Autowired;
import org.springframework.boot.data.jpa.test.autoconfigure.DataJpaTest;
import org.springframework.boot.jdbc.test.autoconfigure.AutoConfigureTestDatabase;

import java.util.Optional;

import static org.assertj.core.api.Assertions.assertThat;

@DataJpaTest
@AutoConfigureTestDatabase(replace = AutoConfigureTestDatabase.Replace.NONE)
class RoleRepositoryTest {

    @Autowired
    private RoleRepository roleRepository;

    private Role buildRole(String name) {
        Role role = new Role();
        role.setName(name);
        role.setDescription(name + " role");
        return role;
    }

    @Test
    void findByName_returnsRole_whenItExists() {
        roleRepository.save(buildRole("USER"));

        Optional<Role> found = roleRepository.findByName("USER");

        assertThat(found).isPresent();
        assertThat(found.get().getDescription()).isEqualTo("USER role");
    }

    @Test
    void findByName_returnsEmpty_whenItDoesNotExist() {
        Optional<Role> found = roleRepository.findByName("MISSING");

        assertThat(found).isEmpty();
    }

    @Test
    void existsByName_returnsTrue_whenRoleExists() {
        roleRepository.save(buildRole("ADMIN"));

        assertThat(roleRepository.existsByName("ADMIN")).isTrue();
    }

    @Test
    void existsByName_returnsFalse_whenRoleDoesNotExist() {
        assertThat(roleRepository.existsByName("MISSING")).isFalse();
    }
}
