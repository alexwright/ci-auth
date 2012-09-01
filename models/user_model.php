<?php
class User_model extends CI_Model {
    protected $table_name = 'users';

    public function create ($username, $email, $password)
    {
        $this->load->library('bcrypt');
        $hash = $this->bcrypt->hash($password);

        $row = array(
            'username'  => $username,
            'email'     => $email,
            'password'  => $hash,
        );

        if ($this->db->insert($this->table_name, $row))
        {
            return $this->db->insert_id();
        }
        return FALSE;
    }

    public function authenticate ($username, $password)
    {
        $user = $this->get_by_username($username);
        if ( ! $user )
        {
            return FALSE;
        }

        $this->load->library('bcrypt');
        if ($this->bcrypt->verify($password, $user->password))
        {
            return $user;
        }
        return FALSE;
    }

    public function get_by_id ($user_id)
    {
        $q = $this->db
            ->where('id', $user_id)
            ->get($this->table_name);
        return $this->get($q);
    }

    public function get_by_username ($username)
    {
        $q = $this->db
            ->where('username', $username)
            ->get($this->table_name);
        return $this->get($q);
    }

    protected function get ($query)
    {
        $r = $query->row();
        return empty($r) ? FALSE : $r;
    }
}
