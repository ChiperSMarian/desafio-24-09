SELECT a.*
FROM alertas_dos a
JOIN clientes c       ON c.id_cliente = a.id_cliente
JOIN tipos_ataques t  ON t.id_tipo    = a.id_tipo
JOIN estado_alerta s  ON s.id_status  = a.id_status
WHERE c.nombre = 'Alhambra'
  AND t.codigo = 'dos'
  AND s.codigo = 'finished'
ORDER BY a.fecha DESC, a.hora DESC;
